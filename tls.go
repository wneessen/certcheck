package certcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"os"
	"strings"
	"time"
)

// STARTTLSProto represents the type of STARTTLS protocol to be used during the certificate check.
//
// This type is an integer-based enumeration for different STARTTLS-supported protocols, such as SMTP, IMAP, or FTP.
type STARTTLSProto int

// STARTTLS protocol types for use in the certificate check.
//
// Constants:
//   - TLSProtoNone: No STARTTLS protocol is used.
//   - TLSProtoSMTP: STARTTLS for the SMTP protocol.
//   - TLSProtoIMAP: STARTTLS for the IMAP protocol.
//   - TLSProtoFTP: STARTTLS for the FTP protocol.
const (
	TLSProtoNone STARTTLSProto = iota
	TLSProtoSMTP
	TLSProtoIMAP
	TLSProtoFTP
)

// checkTLS establishes a TLS connection to the specified IP address and retrieves the server's certificate.
//
// This function uses a context with a configurable timeout to perform the following steps:
//  1. Establish a TCP connection to the host.
//  2. Initialize a TLS client with a specified configuration.
//  3. Perform a TLS handshake to retrieve the server's certificate.
//  4. Record performance metrics for connection establishment, TLS initialization, and the handshake.
//
// Parameters:
//   - ctx: A context.Context to manage the connection timeout.
//   - ip: The IP address of the host to connect to.
//   - metrics: A pointer to a Metrics struct to record timing information.
//
// Returns:
//   - A pointer to the first x509.Certificate from the server.
//   - An error if any step (connection, TLS initialization, or handshake) fails.
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

// checkSTARTTLS establishes a TCP connection to the specified IP address and performs a STARTTLS handshake.
//
// This function uses a context with a configurable timeout to connect to the host, initiate STARTTLS,
// and retrieve the server's certificate. The appropriate STARTTLS protocol (FTP, IMAP, or SMTP) is
// determined by the configuration.
//
// Steps:
//  1. Establish a TCP connection to the host.
//  2. Initiate a STARTTLS handshake based on the specified protocol.
//  3. Retrieve the server's TLS certificate after the handshake.
//  4. Record performance metrics for connection establishment, TLS initialization, and the handshake.
//
// Parameters:
//   - ctx: A context.Context to manage the connection timeout.
//   - ip: The IP address of the host to connect to.
//   - metrics: A pointer to a Metrics struct to record timing information.
//
// Returns:
//   - A pointer to the first x509.Certificate from the server.
//   - An error if any step (connection, STARTTLS handshake, or certificate retrieval) fails.
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
	case TLSProtoFTP:
		connstate, tlsMetrics, err = c.starttlsFTP(conn)
	case TLSProtoIMAP:
		connstate, tlsMetrics, err = c.starttlsIMAP(conn)
	case TLSProtoSMTP:
		connstate, tlsMetrics, err = c.starttlsSMTP(conn)
	default:
		return nil, errors.New("unsupported STARTTLS protocol specified")
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

// starttlsSMTP performs a STARTTLS handshake with an SMTP server.
//
// This function establishes a connection to an SMTP server, issues an EHLO command, verifies STARTTLS
// support, initiates the STARTTLS handshake, and completes the TLS handshake to secure the connection.
// It records performance metrics for initialization and handshake stages.
//
// Steps:
//  1. Read the initial SMTP 220 response.
//  2. Send the EHLO command and verify that the server supports STARTTLS.
//  3. Send the STARTTLS command and initialize the TLS client.
//  4. Perform the TLS handshake and retrieve the connection state.
//  5. Optionally, send a QUIT command to properly terminate the SMTP session.
//
// Parameters:
//   - conn: The established TCP connection to the SMTP server.
//
// Returns:
//   - tls.ConnectionState: The TLS connection state containing details like peer certificates.
//   - Metrics: Performance metrics for the TLS initialization and handshake.
//   - An error if any step in the SMTP communication or STARTTLS handshake fails.
func (c *Checker) starttlsSMTP(conn net.Conn) (tls.ConnectionState, Metrics, error) {
	connstate := tls.ConnectionState{}
	metrics := Metrics{}
	tlsConfig := &tls.Config{InsecureSkipVerify: true, ServerName: c.Config.Certname}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}

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

// starttlsIMAP performs a STARTTLS handshake with an IMAP server.
//
// This function establishes a connection to an IMAP server, issues a CAPABILITY command to check for
// STARTTLS support, initiates the STARTTLS handshake, and completes the TLS handshake to secure the
// connection. It records performance metrics for initialization and handshake stages.
//
// Steps:
//  1. Read the initial IMAP "* OK" greeting.
//  2. Send the CAPABILITY command and verify that the server supports STARTTLS.
//  3. Send the STARTTLS command to initiate the TLS handshake.
//  4. Perform the TLS handshake and retrieve the connection state.
//  5. Optionally, send a LOGOUT command to properly terminate the IMAP session.
//
// Parameters:
//   - conn: The established TCP connection to the IMAP server.
//
// Returns:
//   - tls.ConnectionState: The TLS connection state containing details like peer certificates.
//   - Metrics: Performance metrics for the TLS initialization and handshake.
//   - An error if any step in the IMAP communication or STARTTLS handshake fails.
func (c *Checker) starttlsIMAP(conn net.Conn) (tls.ConnectionState, Metrics, error) {
	connstate := tls.ConnectionState{}
	metrics := Metrics{}
	tlsConfig := &tls.Config{InsecureSkipVerify: true, ServerName: c.Config.Certname}

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

// starttlsFTP performs a STARTTLS handshake with an FTP server.
//
// This function establishes a connection to an FTP server, sends the `AUTH TLS` command to initiate
// STARTTLS, and completes the TLS handshake to secure the connection. It records performance metrics
// for initialization and handshake stages.
//
// Steps:
//  1. Read the initial FTP 220 response.
//  2. Send the `AUTH TLS` command and verify a 234 response.
//  3. Initialize a TLS client and perform the TLS handshake.
//  4. Retrieve the connection state after the handshake.
//  5. Optionally, send a `QUIT` command to properly terminate the FTP session.
//
// Parameters:
//   - conn: The established TCP connection to the FTP server.
//
// Returns:
//   - tls.ConnectionState: The TLS connection state containing details like peer certificates.
//   - Metrics: Performance metrics for the TLS initialization and handshake.
//   - An error if any step in the FTP communication or STARTTLS handshake fails.
func (c *Checker) starttlsFTP(conn net.Conn) (tls.ConnectionState, Metrics, error) {
	connstate := tls.ConnectionState{}
	metrics := Metrics{}
	tlsConfig := &tls.Config{InsecureSkipVerify: true, ServerName: c.Config.Certname}

	timer := time.Now()
	text := textproto.NewConn(conn)
	_, _, err := text.ReadResponse(220)
	if err != nil {
		metrics.TLSInit = time.Since(timer)
		return connstate, metrics, fmt.Errorf("expected FTP server to respond with 220 status, got: %w", err)
	}
	id, err := text.Cmd("AUTH TLS")
	if err != nil {
		metrics.TLSInit = time.Since(timer)
		return connstate, metrics, fmt.Errorf("failed to send AUTH TLS command to FTP server: %w", err)
	}
	text.StartResponse(id)
	code, msg, err := text.ReadResponse(234)
	if err != nil {
		metrics.TLSInit = time.Since(timer)
		return connstate, metrics, fmt.Errorf("unexpected respsonse to AUTH TLS from FTP server: %d %s", code, msg)
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
		return connstate, metrics, fmt.Errorf("failed to send QUIT command to FTP server: %w", err)
	}
	text.StartResponse(id)
	code, msg, err = text.ReadResponse(221)
	if err != nil {
		return connstate, metrics, fmt.Errorf("unexpected respsonse to QUIT command from FTP server: %d %s", code, msg)
	}
	text.EndResponse(id)

	return connstate, metrics, nil
}
