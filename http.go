package certcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"
)

func (c *Checker) checkHTTP(ctx context.Context, ip net.IP) (*x509.Certificate, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, c.connTimeout)
	defer cancel()

	dialer := net.Dialer{}
	tlsConfig := &tls.Config{InsecureSkipVerify: true, ServerName: c.certname}
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", c.port))

	// Connect to host
	timer := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, time.Since(timer), fmt.Errorf("failed to connect to host %q: %w", addr, err)
	}
	defer func() {
		if err = conn.Close(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to close connection to host %q: %s\n", addr, err)
		}
	}()

	// Initialize TLS client
	client := tls.Client(conn, tlsConfig)
	if err = client.HandshakeContext(ctx); err != nil {
		return nil, time.Since(timer), fmt.Errorf("failed to perform TLS handshake with host %q: %w", addr, err)
	}

	// Return the certificate
	connstate := client.ConnectionState()
	if len(connstate.PeerCertificates) <= 0 {
		return nil, time.Since(timer), fmt.Errorf("no peer certificate found for host %q", addr)
	}
	return connstate.PeerCertificates[0], time.Since(timer), nil
}
