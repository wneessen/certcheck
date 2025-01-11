package certcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/textproto"
	"os"
	"strings"
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
	ctx, cancel := context.WithTimeout(ctx, c.Config.ConnTimeout)
	defer cancel()

	dialer := net.Dialer{}
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

	// Check for STARTTLS support
	var connstate tls.ConnectionState
	var tlsMetrics Metrics
	switch c.Config.StartTLS {
	case TLSProtoSMTP:
		connstate, tlsMetrics, err = c.starttlsSMTP(conn)
	case TLSProtoIMAP:
		connstate, tlsMetrics, err = c.starttlsIMAP(conn)
	default:
	}
	metrics.TLSInit = tlsMetrics.TLSInit
	metrics.TLSHandshake = tlsMetrics.TLSHandshake
	if err != nil {
		return nil, fmt.Errorf("unable to STARTTLS on %q: %w", addr, err)
	}

	if len(connstate.PeerCertificates) <= 0 {
		return nil, fmt.Errorf("no peer certificate found for host %q", addr)
	}
	return connstate.PeerCertificates[0], nil
}

func (c *Checker) starttlsSMTP(conn net.Conn) (tls.ConnectionState, Metrics, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	tlsConfig := &tls.Config{InsecureSkipVerify: true, ServerName: c.Config.Certname}
	metrics := Metrics{}
	connstate := tls.ConnectionState{}

	timer := time.Now()
	text := textproto.NewConn(conn)
	_, _, err = text.ReadResponse(220)
	if err != nil {
		metrics.TLSInit = time.Since(timer)
		return connstate, metrics, fmt.Errorf("expected SMTP server to respond with 220 status, got: %w", err)
	}
	id, err := text.Cmd("EHLO %s", hostname)
	if err != nil {
		metrics.TLSInit = time.Since(timer)
		return connstate, metrics, fmt.Errorf("failed to send EHLO command to SMTP server: %w", err)
	}
	text.StartResponse(id)
	code, msg, err := text.ReadResponse(250)
	if err != nil {
		metrics.TLSInit = time.Since(timer)
		return connstate, metrics, fmt.Errorf("unexpected respsonse to EHLO from SMTP server: %d %s", code, msg)
	}
	text.EndResponse(id)

	if !strings.Contains(msg, "STARTTLS") {
		metrics.TLSInit = time.Since(timer)
		return connstate, metrics, fmt.Errorf("SMTP server does not support STARTTLS")
	}
	id, err = text.Cmd("STARTTLS")
	if err != nil {
		metrics.TLSInit = time.Since(timer)
		return connstate, metrics, fmt.Errorf("failed to send EHLO command to SMTP server: %w", err)
	}
	text.StartResponse(id)
	code, msg, err = text.ReadResponse(220)
	if err != nil {
		metrics.TLSInit = time.Since(timer)
		return connstate, metrics, fmt.Errorf("unexpected respsonse to STARTTLS command from SMTP server: %d %s", code, msg)
	}
	text.EndResponse(id)
	client := tls.Client(conn, tlsConfig)
	metrics.TLSInit = time.Since(timer)

	if err = client.Handshake(); err != nil {
		metrics.TLSHandshake = time.Since(timer)
		return connstate, metrics, fmt.Errorf("failed to perform TLS handshake with host: %w", err)
	}
	metrics.TLSHandshake = time.Since(timer)
	connstate = client.ConnectionState()

	text = textproto.NewConn(client)
	id, err = text.Cmd("QUIT")
	if err != nil {
		return connstate, metrics, fmt.Errorf("failed to send QUIT command to SMTP server: %w", err)
	}
	text.StartResponse(id)
	code, msg, err = text.ReadResponse(221)
	if err != nil {
		return connstate, metrics, fmt.Errorf("unexpected respsonse to QUIT command from SMTP server: %d %s", code, msg)
	}
	text.EndResponse(id)

	return connstate, metrics, nil
}

func (c *Checker) starttlsIMAP(conn net.Conn) (tls.ConnectionState, Metrics, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true, ServerName: c.Config.Certname}
	metrics := Metrics{}
	connstate := tls.ConnectionState{}
	var err error

	timer := time.Now()
	text := textproto.NewConn(conn)
	msg, err := text.ReadLine()
	if err != nil || !strings.HasPrefix(msg, "* OK") {
		metrics.TLSInit = time.Since(timer)
		return connstate, metrics, fmt.Errorf("expected IMAP server to respond with OK status, got: %w", err)
	}
	id, err := text.Cmd("A001 CAPABILITY")
	if err != nil {
		metrics.TLSInit = time.Since(timer)
		return connstate, metrics, fmt.Errorf("failed to send CAPABILITY command to IMAP server: %w", err)
	}
	text.StartResponse(id)
	msg, err = text.ReadLine()
	if err != nil {
		metrics.TLSInit = time.Since(timer)
		return connstate, metrics, fmt.Errorf("unexpected respsonse to CAPABILITY command from IMAP server: %s", msg)
	}
	okmsg, err := text.ReadLine()
	if err != nil {
		metrics.TLSInit = time.Since(timer)
		return connstate, metrics, fmt.Errorf("unexpected respsonse to CAPABILITY command from IMAP server: %s", msg)
	}
	text.EndResponse(id)
	if !strings.HasPrefix(okmsg, "A001 OK") || !strings.Contains(msg, "STARTTLS") {
		metrics.TLSInit = time.Since(timer)
		return connstate, metrics, fmt.Errorf("unexpected respsonse to CAPABILITY command from IMAP server: %s", okmsg)
	}

	id, err = text.Cmd("A002 STARTTLS")
	if err != nil {
		metrics.TLSInit = time.Since(timer)
		return connstate, metrics, fmt.Errorf("failed to send STARTTLS command to IMAP server: %w", err)
	}
	text.StartResponse(id)
	msg, err = text.ReadLine()
	if err != nil {
		metrics.TLSInit = time.Since(timer)
		return connstate, metrics, fmt.Errorf("unexpected respsonse to STARTTLS command from IMAP server: %s", msg)
	}
	text.EndResponse(id)
	if !strings.HasPrefix(msg, "A002 OK") {
		metrics.TLSInit = time.Since(timer)
		return connstate, metrics, fmt.Errorf("unexpected respsonse to STARTTLS command from IMAP server: %s", msg)
	}

	client := tls.Client(conn, tlsConfig)
	metrics.TLSInit = time.Since(timer)

	if err = client.Handshake(); err != nil {
		metrics.TLSHandshake = time.Since(timer)
		return connstate, metrics, fmt.Errorf("failed to perform TLS handshake with host: %w", err)
	}
	metrics.TLSHandshake = time.Since(timer)
	connstate = client.ConnectionState()

	text = textproto.NewConn(client)
	id, err = text.Cmd("A003 LOGOUT")
	if err != nil {
		return connstate, metrics, fmt.Errorf("failed to send LOGOUT command to IMAP server: %w", err)
	}
	text.StartResponse(id)
	msg, err = text.ReadLine()
	if err != nil {
		return connstate, metrics, fmt.Errorf("unexpected respsonse to LOGOUT command from IMAP server: %s", msg)
	}
	text.EndResponse(id)
	if !strings.HasPrefix(msg, "* BYE") {
		return connstate, metrics, fmt.Errorf("unexpected respsonse to LOGOUT command from IMAP server: %s", msg)
	}

	return connstate, metrics, nil
}
