// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

// Package certcheck implements a certificate checker.
//
// This package provides functionality to perform certificate validation and connection diagnostics,
// including DNS lookups, connection establishment, and optional TLS handshake verification. It supports
// checking certificates for various protocols, including standard TLS and STARTTLS for SMTP, IMAP, and FTP.
package certcheck

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

const (
	// DefaultTimeout is the default timeout used for operations when no specific timeout is provided.
	DefaultTimeout = time.Second * 5

	// DefaultRetries is the default number of retries for DNS lookups.
	DefaultRetries = 3

	// DefaultPort is the default port used for TLS connections (443).
	DefaultPort = 443
)

// Checker represents a certificate checker instance.
//
// Fields:
//   - Config: The configuration settings used for the certificate check.
type Checker struct {
	Config Config
}

// Config holds the configuration settings for a certificate check.
//
// Fields:
//   - Certname: The name of the certificate to verify, defaults to the Hostname if not provided.
//   - ConnTimeout: The timeout for establishing a connection.
//   - DNSTimeout: The timeout for DNS lookups.
//   - Hostname: The hostname of the server to connect to.
//   - Port: The port to connect to, defaults to 443 if not specified.
//   - DNSRetries: The number of retries for DNS lookups, defaults to a reasonable value.
//   - StartTLS: The STARTTLS protocol to use, if applicable (e.g., SMTP, IMAP, FTP).
//   - VerifyCert: A flag indicating whether to verify the certificate against the Certname.
type Config struct {
	Certname    string
	ConnTimeout time.Duration
	DNSTimeout  time.Duration
	Hostname    string
	Port        uint
	DNSRetries  uint
	StartTLS    STARTTLSProto
	VerifyCert  bool
}

// Metrics captures performance metrics for various stages of a certificate check.
//
// Fields:
//   - ConnTime: The duration of the connection establishment.
//   - DNSLookup: The duration of the DNS lookup.
//   - TLSInit: The duration of the TLS initialization phase.
//   - TLSHandshake: The duration of the TLS handshake process.
type Metrics struct {
	ConnTime     time.Duration
	DNSLookup    time.Duration
	TLSInit      time.Duration
	TLSHandshake time.Duration
}

// Result represents the outcome of a certificate check.
//
// Fields:
//   - CertExpire: The expiration time of the checked certificate.
//   - Metrics: A pointer to the Metrics structure containing performance data for the check.
//   - Severity: The severity level of the result, indicating the status or issues detected.
type Result struct {
	Addresses  []net.IP
	CertExpire time.Time
	Metrics    *Metrics
	Severity   Severity
}

// New initializes a new Checker instance with the provided configuration.
//
// This function ensures that default values are applied to configuration fields if they are not explicitly set:
//   - DNSTimeout defaults to DefaultTimeout if not specified.
//   - ConnTimeout defaults to DefaultTimeout if not specified.
//   - Port defaults to DefaultPort (443) if not specified.
//   - Certname defaults to the Hostname if not explicitly provided.
//
// Parameters:
//   - config: A Config struct containing the desired configuration settings.
//
// Returns:
//   - A pointer to the initialized Checker instance.
func New(config Config) *Checker {
	if config.DNSTimeout == 0 {
		config.DNSTimeout = DefaultTimeout
	}
	if config.ConnTimeout == 0 {
		config.ConnTimeout = DefaultTimeout
	}
	if config.Port == 0 {
		config.Port = DefaultPort
	}
	if config.Certname == "" {
		config.Certname = config.Hostname
	}
	if config.DNSRetries == 0 {
		config.DNSRetries = DefaultRetries
	}
	return &Checker{Config: config}
}

// Check performs a certificate check for the configured host.
//
// This function resolves the hostname to its IP address, establishes a connection, and optionally
// verifies the TLS certificate. It supports STARTTLS protocols (e.g., SMTP, IMAP, FTP) or standard TLS.
//
// Steps:
//  1. Perform a DNS lookup with retries based on the configuration.
//  2. Connect to the resolved IP address and determine the TLS or STARTTLS protocol.
//  3. Retrieve and optionally verify the server's certificate.
//  4. Capture performance metrics for each step.
//
// Parameters:
//   - ctx: A context.Context used for managing timeouts and cancellations.
//
// Returns:
//   - A Result struct containing the certificate's expiration time, performance metrics, and severity level.
//   - An error if any step in the process (DNS lookup, connection, or certificate validation) fails.
func (c *Checker) Check(ctx context.Context) (Result, error) {
	if c.Config.Hostname == "" {
		return Result{}, fmt.Errorf("hostname is required")
	}
	if ctx == nil {
		return Result{}, fmt.Errorf("context must not be nil")
	}

	var addrs []net.IP
	var dnsFails uint = 1
	result := Result{Metrics: &Metrics{}}

	// DNS lookup
	for {
		var err error
		addrs, err = c.lookupHost(ctx, result.Metrics)
		if err != nil {
			if dnsFails < c.Config.DNSRetries {
				dnsFails++
				continue
			}
			if dnsFails >= c.Config.DNSRetries {
				result.Severity = SeverityCritical
				return result, fmt.Errorf("DNS lookup failed after %d retries: %w", c.Config.DNSRetries, err)
			}
		}
		break
	}
	if len(addrs) == 0 {
		result.Severity = SeverityCritical
		return result, fmt.Errorf("no IP address found for hostname %s", c.Config.Hostname)
	}
	addr := addrs[0]
	result.Addresses = addrs

	// Connect and optionally verify TLS certificate
	var cert *x509.Certificate
	var err error
	switch c.Config.StartTLS {
	case TLSProtoFTP, TLSProtoIMAP, TLSProtoSMTP:
		cert, err = c.checkSTARTTLS(ctx, addr, result.Metrics)
	default:
		cert, err = c.checkTLS(ctx, addr, result.Metrics)
	}
	if err != nil {
		result.Severity = SeverityCritical
		return result, fmt.Errorf("failed to connect to host %s: %w", c.Config.Hostname, err)
	}
	if cert == nil {
		result.Severity = SeverityCritical
		return result, fmt.Errorf("no certificate found for %q on host %s:%d", c.Config.Certname, c.Config.Hostname,
			c.Config.Port)
	}
	if c.Config.VerifyCert {
		if err := cert.VerifyHostname(c.Config.Certname); err != nil {
			result.Severity = SeverityCritical
			return result, fmt.Errorf("failed to verify certificate name %q on host %s:%d: %w", c.Config.Certname,
				c.Config.Hostname, c.Config.Port, err)
		}
	}

	result.CertExpire = cert.NotAfter
	return result, nil
}
