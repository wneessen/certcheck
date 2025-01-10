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

type STARTTLSProto int

const (
	TLSProtoNone STARTTLSProto = iota
	TLSProtoSMTP
	TLSProtoIMAP
)

func (c *Checker) checkTLS(ctx context.Context, ip net.IP, metrics *Metrics) (*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Config.ConnTimeout)
	defer cancel()

	dialer := net.Dialer{}
	tlsConfig := &tls.Config{InsecureSkipVerify: true, ServerName: c.Config.Certname}
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", c.Config.Port))

	// Connect to host
	timer := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	metrics.ConnTime = time.Since(timer)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to host %q: %w", addr, err)
	}
	defer func() {
		if err = conn.Close(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to close connection to host %q: %s\n", addr, err)
		}
	}()

	// Initialize TLS client
	timer = time.Now()
	client := tls.Client(conn, tlsConfig)
	metrics.TLSInit = time.Since(timer)

	timer = time.Now()
	if err = client.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to perform TLS handshake with host %q: %w", addr, err)
	}
	metrics.TLSHandshake = time.Since(timer)

	connstate := client.ConnectionState()
	if len(connstate.PeerCertificates) <= 0 {
		return nil, fmt.Errorf("no peer certificate found for host %q", addr)
	}
	return connstate.PeerCertificates[0], nil
}

func (c *Checker) checkSTARTTLS(ctx context.Context, ip net.IP, metrics *Metrics) (*x509.Certificate, error) {
	return nil, nil
}
