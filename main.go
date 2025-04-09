package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/libp2p/go-reuseport"
	"golang.org/x/sys/unix"
)

// 全局配置
const (
	ListenAddr    = ":8080"
	CAKeyPath     = "ca.key"
	CACertPath    = "ca.crt"
	CertCacheSize = 100
)

var (
	RedirectRules = map[string]string{
		"ghcr.io": "https://ghcr.m.daocloud.io",
	}
	certCache sync.Map
)

// 连接池结构
type ConnPool struct {
	mu    sync.Mutex
	conns map[string][]net.Conn
}

func NewConnPool() *ConnPool {
	return &ConnPool{conns: make(map[string][]net.Conn)}
}

func (p *ConnPool) Get(addr string) (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if conns := p.conns[addr]; len(conns) > 0 {
		conn := conns[len(conns)-1]
		p.conns[addr] = conns[:len(conns)-1]
		return conn, nil
	}

	return net.Dial("tcp", addr)
}

func (p *ConnPool) Put(addr string, conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.conns[addr] = append(p.conns[addr], conn)
}

var pool = NewConnPool()

// 证书管理
func generateCA() error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "MITM Proxy CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	keyOut, err := os.Create(CAKeyPath)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	certOut, err := os.Create(CACertPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	return pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func isCAInstalled() bool {
	switch runtime.GOOS {
	case "linux":
		if _, err := os.Stat("/usr/local/share/ca-certificates/mitm-proxy.crt"); err == nil {
			return true
		}
	case "darwin":
		cmd := exec.Command("security", "find-certificate", "-c", "MITM Proxy CA")
		return cmd.Run() == nil
	case "windows":
		cmd := exec.Command("certutil", "-viewstore", "Root")
		out, _ := cmd.CombinedOutput()
		return strings.Contains(string(out), "MITM Proxy CA")
	}
	return false
}

func runWithElevatedPrivilege(args ...string) error {
	switch runtime.GOOS {
	case "linux", "darwin":
		cmd := exec.Command("sudo", args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	case "windows":
		cmd := exec.Command("runas", "/user:Administrator", strings.Join(args, " "))
		cmd.Stdin = os.Stdin
		return cmd.Run()
	}
	return nil
}

func installCA() error {
	if isCAInstalled() {
		return nil
	}

	if os.Geteuid() != 0 && runtime.GOOS != "windows" {
		log.Println("Requesting elevation to install CA certificate...")
		switch runtime.GOOS {
		case "linux":
			return runWithElevatedPrivilege(
				"sh", "-c",
				fmt.Sprintf("cp %s /usr/local/share/ca-certificates/mitm-proxy.crt && update-ca-certificates", CACertPath),
			)
		case "darwin":
			return runWithElevatedPrivilege(
				"security", "add-trusted-cert", "-d", "-k", "/Library/Keychains/System.keychain", CACertPath,
			)
		case "windows":
			return runWithElevatedPrivilege(
				"certutil", "-addstore", "Root", CACertPath,
			)
		}
	}

	switch runtime.GOOS {
	case "linux":
		if err := exec.Command("cp", CACertPath, "/usr/local/share/ca-certificates/mitm-proxy.crt").Run(); err != nil {
			return err
		}
		return exec.Command("update-ca-certificates").Run()
	case "darwin":
		return exec.Command("security", "add-trusted-cert", "-d", "-k", "/Library/Keychains/System.keychain", CACertPath).Run()
	case "windows":
		return exec.Command("certutil", "-addstore", "Root", CACertPath).Run()
	}
	return nil
}

func getCert(host string) (*tls.Certificate, error) {
	if cert, ok := certCache.Load(host); ok {
		return cert.(*tls.Certificate), nil
	}

	caCert, err := os.ReadFile(CACertPath)
	if err != nil {
		return nil, err
	}
	caBlock, _ := pem.Decode(caCert)
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, err
	}

	caKey, err := os.ReadFile(CAKeyPath)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(caKey)
	priv, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{host},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, ca, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	if certCache.Size() >= CertCacheSize {
		certCache.Range(func(key, _ interface{}) bool {
			certCache.Delete(key)
			return false
		})
	}
	certCache.Store(host, cert)
	return cert, nil
}

// 代理逻辑
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func copyResponse(dst io.Writer, src io.Reader) {
	buf := make([]byte, 32*1024)
	io.CopyBuffer(dst, src, buf)
}

func buildRedirectResponse(dest string) []byte {
	buf := bytes.Buffer{}
	fmt.Fprintf(&buf, "HTTP/1.1 307 Temporary Redirect\r\n")
	fmt.Fprintf(&buf, "Location: %s\r\n", dest)
	fmt.Fprintf(&buf, "Connection: close\r\n\r\n")
	return buf.Bytes()
}

func handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if dest := RedirectRules[r.Host]; dest != "" {
		http.Redirect(w, r, dest, http.StatusTemporaryRedirect)
		return
	}

	conn, err := pool.Get(r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer pool.Put(r.Host, conn)

	r.Write(conn)
	resp, err := http.ReadResponse(bufio.NewReader(conn), r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	copyResponse(w, resp.Body)
}

func handleTLS(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	tlsConn := tls.Server(clientConn, &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return getCert(chi.ServerName)
		},
	})
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		log.Println("TLS handshake error:", err)
		return
	}

	req, err := http.ReadRequest(bufio.NewReader(tlsConn))
	if err != nil {
		return
	}

	if dest := RedirectRules[req.Host]; dest != "" {
		tlsConn.Write(buildRedirectResponse(dest))
		return
	}

	targetAddr := req.Host
	if !strings.Contains(targetAddr, ":") {
		targetAddr += ":443"
	}

	serverConn, err := pool.Get(targetAddr)
	if err != nil {
		return
	}
	defer pool.Put(targetAddr, serverConn)

	req.Write(serverConn)
	resp, err := http.ReadResponse(bufio.NewReader(serverConn), req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	resp.Write(tlsConn)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		handleTLS(w, r)
	} else {
		handlePlainHTTP(w, r)
	}
}

func main() {
	if _, err := os.Stat(CACertPath); os.IsNotExist(err) {
		if err := generateCA(); err != nil {
			log.Fatal("Generate CA failed:", err)
		}
	}

	if err := installCA(); err != nil {
		log.Fatal("Install CA failed:", err)
	}

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
		},
	}

	listener, err := lc.Listen(context.Background(), "tcp", ListenAddr)
	if err != nil {
		log.Fatal("Listen failed:", err)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(handleRequest),
		TLSConfig: &tls.Config{
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return getCert(chi.ServerName)
			},
		},
	}

	log.Println("Proxy server started on", ListenAddr)
	log.Fatal(server.Serve(listener))
}
