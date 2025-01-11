package certcheck

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
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// PortAdder is an atomic counter used to increment port numbers for the test SMTP server instances.
var PortAdder atomic.Int32

// TestServerPortBase is the base port for the test server
var TestServerPortBase int32 = 20443

func TestNew(t *testing.T) {
	t.Run("New with defaults", func(t *testing.T) {
		config := Config{}
		checker := New(config)
		if checker == nil {
			t.Fatal("failed to get checker instance, New() returned nil")
		}
		if checker.Config.DNSTimeout != DefaultTimeout {
			t.Errorf("expected DNSTimeout to be %s, got %s", DefaultTimeout, checker.Config.DNSTimeout)
		}
		if checker.Config.ConnTimeout != DefaultTimeout {
			t.Errorf("expected ConnTimeout to be %s, got %s", DefaultTimeout, checker.Config.ConnTimeout)
		}
		if checker.Config.Port != DefaultPort {
			t.Errorf("expected Port to be %d, got %d", DefaultPort, checker.Config.Port)
		}
		if checker.Config.DNSRetries != DefaultRetries {
			t.Errorf("expected DNSRetries to be %d, got %d", DefaultRetries, checker.Config.DNSRetries)
		}
	})
	t.Run("New with hostname", func(t *testing.T) {
		config := Config{Hostname: "example.com"}
		checker := New(config)
		if checker == nil {
			t.Fatal("failed to get checker instance, New() returned nil")
		}
		if checker.Config.Hostname != "example.com" {
			t.Errorf("expected Hostname to be %s, got %s", "example.com", checker.Config.Hostname)
		}
		if checker.Config.Certname != "example.com" {
			t.Errorf("expected Certname to be %s, got %s", "example.com", checker.Config.Certname)
		}
	})
	t.Run("New with hostname and certname", func(t *testing.T) {
		config := Config{Hostname: "example.com", Certname: "sub.example.com"}
		checker := New(config)
		if checker == nil {
			t.Fatal("failed to get checker instance, New() returned nil")
		}
		if checker.Config.Hostname != "example.com" {
			t.Errorf("expected Hostname to be %s, got %s", "example.com", checker.Config.Hostname)
		}
		if checker.Config.Certname != "sub.example.com" {
			t.Errorf("expected Certname to be %s, got %s", "sub.example.com", checker.Config.Certname)
		}
	})
}

func TestCheck(t *testing.T) {
	t.Run("Check with valid hostname", func(t *testing.T) {
		checker, ip := defaultChecker(t)
		result, err := checker.Check(context.Background())
		if err != nil {
			t.Fatalf("failed to check certificate: %s", err)
		}
		if result.Addresses[0].String() != ip.String() {
			t.Errorf("expected IP address to be %s, got %s", ip, result.Addresses[0])
		}

	})
	t.Run("Check with empty hostname", func(t *testing.T) {
		config := Config{}
		checker := New(config)
		_, err := checker.Check(nil)
		if err == nil {
			t.Fatal("expected check to fail with empty hostname")
		}
		expErr := "hostname is required"
		if !strings.EqualFold(err.Error(), expErr) {
			t.Errorf("expected error to be %s, got %s", expErr, err)
		}
	})
	t.Run("Check with nil context", func(t *testing.T) {
		config := Config{Hostname: "invalid"}
		checker := New(config)
		_, err := checker.Check(nil)
		if err == nil {
			t.Fatal("expected check to fail with invalid hostname")
		}
		expErr := "context must not be nil"
		if !strings.EqualFold(err.Error(), expErr) {
			t.Errorf("expected error to be %s, got %s", expErr, err)
		}
	})
	t.Run("Check with invalid hostname", func(t *testing.T) {
		config := Config{Hostname: "invalid"}
		checker := New(config)
		_, err := checker.Check(context.Background())
		if err == nil {
			t.Fatal("expected check to fail with invalid hostname")
		}
		expErr := "DNS lookup failed after 3 retries: failed to lookup IP(s) for host invalid: lookup invalid"
		if !strings.Contains(err.Error(), expErr) {
			t.Errorf("expected error to contain %s, got %s", expErr, err)
		}
	})
}

func TestGenCert(t *testing.T) {
	props, err := testServerProps(t, false, 0)
	if err != nil {
		t.Fatalf("failed to get test server properties: %s", err)
	}
	go func() {
		if err := testHTTPserver(t, props); err != nil {
			t.Errorf("failed to start test HTTP server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 30)
	t.Log("Port", props.ListenPort)
	time.Sleep(time.Minute * 500)
}

// defaultChecker is a test helper method that returns a Checker and a matching IP address for
// the configured hostname
func defaultChecker(t *testing.T) (*Checker, net.IP) {
	t.Helper()
	hostname := "web.neessen.cloud"
	ip := net.ParseIP("49.12.112.91")
	config := Config{Hostname: hostname, Port: 443}
	checker := New(config)
	return checker, ip
}

// genTestCert is a test helper method to generate certificates for test servers
func genTestCert(t *testing.T, validFor time.Duration, cn string, ca bool) ([]byte, []byte, error) {
	t.Helper()

	// If no validity is given, we generate for one day
	if validFor == 0 {
		validFor = time.Hour * 24
	}

	// Generate private key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Set validity dates
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)

	// Generate random serial
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	// Generate certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ACME Co."},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	cns := strings.Split(cn, ",")
	for _, h := range cns {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if ca {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	// Generate certifcate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, privKey.Public(), privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %s", err)
	}

	public := bytes.NewBuffer(nil)
	if err = pem.Encode(public, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, nil, fmt.Errorf("failed to encode certificate: %w", err)
	}

	private := bytes.NewBuffer(nil)
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	if err = pem.Encode(private, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, nil, fmt.Errorf("failed to encode private key: %w", err)
	}
	return public.Bytes(), private.Bytes(), nil
}

func testServerProps(t *testing.T, notls bool, validfor time.Duration) (*serverProps, error) {
	t.Helper()
	public, private, err := genTestCert(t, validfor, "127.0.0.1,localhost", false)
	if err != nil {
		return nil, fmt.Errorf("unable to provide testserver config: %w", err)
	}
	serverPort := uint(TestServerPortBase + PortAdder.Load())
	return &serverProps{
		ListenPort: serverPort,
		NoTLS:      notls,
		ServerKey:  private,
		ServerCert: public,
	}, nil
}

// serverProps represents the configuration properties for the SMTP server.
type serverProps struct {
	BufferMutex sync.RWMutex
	EchoBuffer  io.Writer
	ListenPort  uint
	NoTLS       bool
	TLSProto    STARTTLSProto
	ServerCert  []byte
	ServerKey   []byte
}

// simpleSMTPServer starts a simple TCP server that resonds to SMTP commands.
// The provided featureSet represents in what the server responds to EHLO command
// failReset controls if a RSET succeeds
func testserver(ctx context.Context, t *testing.T, props *serverProps) error {
	t.Helper()
	if props == nil {
		return fmt.Errorf("no server properties provided")
	}

	keypair, err := tls.X509KeyPair(props.ServerCert, props.ServerKey)
	if err != nil {
		return fmt.Errorf("failed to read TLS keypair: %w", err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{keypair}}

	var listener net.Listener
	listenAddr := net.JoinHostPort("localhost", fmt.Sprintf("%d", props.ListenPort))
	if props.NoTLS {
		listener, err = net.Listen("tcp", listenAddr)
	} else {
		listener, err = tls.Listen("tcp", listenAddr, tlsConfig)
	}
	if err != nil {
		return fmt.Errorf("unable to listen on %q: %w (TLS: %t)", listenAddr, err, !props.NoTLS)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			t.Logf("failed to close listener: %s", err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			conn, err := listener.Accept()
			var opErr *net.OpError
			if err != nil {
				if errors.As(err, &opErr) && opErr.Temporary() {
					continue
				}
				return fmt.Errorf("unable to accept conn: %w", err)
			}
			handleTestServerConnection(conn, t, props)
		}
	}
}

func handleTestServerConnection(conn net.Conn, t *testing.T, props *serverProps) {
	t.Helper()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	writeLine := func(data string) {
		_, err := writer.WriteString(data + "\r\n")
		if err != nil {
			t.Logf("failed to write line: %s", err)
		}
		if props.EchoBuffer != nil {
			props.BufferMutex.Lock()
			if _, berr := props.EchoBuffer.Write([]byte(data + "\r\n")); berr != nil {
				t.Errorf("failed write to echo buffer: %s", berr)
			}
			props.BufferMutex.Unlock()
		}
		_ = writer.Flush()
	}

	writeLine("Cool")
	for {
		data, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		t.Log(data)
	}
}

func testHTTPserver(t *testing.T, props *serverProps) error {
	t.Helper()
	if props == nil {
		return fmt.Errorf("no server properties provided")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	certfile, err := os.CreateTemp("", "certcheck-http-cert-*.pem")
	if err != nil {
		return fmt.Errorf("failed to create temporary cert file: %w", err)
	}
	defer func() {
		if err := certfile.Close(); err != nil {
			t.Errorf("failed to close cert file: %s", err)
		}
	}()
	if _, err = certfile.Write(props.ServerCert); err != nil {
		return fmt.Errorf("failed to write to cert file: %w", err)
	}

	keyfile, err := os.CreateTemp("", "certcheck-http-key-*.pem")
	if err != nil {
		return fmt.Errorf("failed to create temporary key file: %w", err)
	}
	defer func() {
		if err := keyfile.Close(); err != nil {
			t.Errorf("failed to close key file: %s", err)
		}
	}()
	if _, err = keyfile.Write(props.ServerKey); err != nil {
		return fmt.Errorf("failed to write to key file: %w", err)
	}

	listenAddr := net.JoinHostPort("", fmt.Sprintf("%d", props.ListenPort))
	return http.ListenAndServeTLS(listenAddr, certfile.Name(), keyfile.Name(), handler)
}
