// Package certcheck implements a certificate checker
package certcheck

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

const DefaultTimeout = 5 * time.Second

type Checker struct {
	certname    string
	connTimeout time.Duration
	dnsTimeout  time.Duration
	hostname    string
	port        uint
	dnsRetries  uint
	starttls    STARTTLSProto
	verify      bool
}
type Status struct {
	ConnTime   time.Duration
	DNSLookup  time.Duration
	Expiration time.Time
	Status     Severity
}

func (c *Checker) Certname() string {
	return c.certname
}

func (c *Checker) Hostname() string {
	return c.hostname
}

func (c *Checker) Port() uint {
	return c.port
}

func New(hostname, certname string, port uint, starttls STARTTLSProto, conntimeout, dnstimeout time.Duration,
	dnsRetries uint, verify bool,
) *Checker {
	if conntimeout == 0 {
		conntimeout = DefaultTimeout
	}
	if dnstimeout == 0 {
		dnstimeout = DefaultTimeout
	}
	if certname == "" {
		certname = hostname
	}

	return &Checker{
		certname:    certname,
		connTimeout: conntimeout,
		dnsTimeout:  dnstimeout,
		hostname:    hostname,
		port:        port,
		dnsRetries:  dnsRetries,
		starttls:    starttls,
		verify:      verify,
	}
}

func (c *Checker) Check(ctx context.Context) (Status, error) {
	var addrs []net.IP
	var cert *x509.Certificate
	var connErr error
	var connTime, dnsLookup time.Duration
	var dnsFails uint = 1
	var status Status

	// DNS lookup
	for {
		var err error
		addrs, dnsLookup, err = c.lookupHost(ctx)
		if err != nil {
			if dnsFails < c.dnsRetries {
				dnsFails++
				continue
			}
			if dnsFails >= c.dnsRetries {
				status.Status = SeverityCritical
				status.DNSLookup = dnsLookup
				return status, fmt.Errorf("DNS lookup failed after %d retries: %w", c.dnsRetries, err)
			}
		}
		break
	}
	status.DNSLookup = dnsLookup
	if len(addrs) == 0 {
		status.Status = SeverityCritical
		return status, fmt.Errorf("no IP address found for hostname %s", c.hostname)
	}
	addr := addrs[0]

	// Connect and optionally verify TLS certificate
	switch c.starttls {
	case TLSProtoSMTP, TLSProtoIMAP:
	default:
		cert, connTime, connErr = c.checkHTTP(ctx, addr)
	}
	status.ConnTime = connTime
	if connErr != nil {
		status.Status = SeverityCritical
		return status, fmt.Errorf("failed to connect to host %s: %w", c.hostname, connErr)
	}
	if cert == nil {
		status.Status = SeverityCritical
		return status, fmt.Errorf("no certificate found for %q on host %s:%d", c.certname, c.hostname, c.port)
	}
	if c.verify {
		if err := cert.VerifyHostname(c.certname); err != nil {
			status.Status = SeverityCritical
			return status, fmt.Errorf("failed to verify certificate name %q on host %s:%d: %s ", c.certname,
				c.hostname, c.port, err)
		}
	}

	status.Expiration = cert.NotAfter
	return status, nil
}
