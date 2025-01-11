// Package certcheck implements a certificate checker
package certcheck

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

const (
	// DefaultTimeout is the default timeout that is used when no specific timeouts are requested
	DefaultTimeout = time.Second * 5
	DefaultRetries = 3
	DefaultPort    = 443
)

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
type Checker struct {
	Config Config
}
type Metrics struct {
	ConnTime     time.Duration
	DNSLookup    time.Duration
	TLSInit      time.Duration
	TLSHandshake time.Duration
}

type Result struct {
	CertExpire time.Time
	Metrics    *Metrics
	Severity   Severity
}

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
	return &Checker{Config: config}
}

func (c *Checker) Check(ctx context.Context) (Result, error) {
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
