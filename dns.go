package certcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

func (c *Checker) lookupHost(ctx context.Context) ([]net.IP, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, c.dnsTimeout)
	defer cancel()
	resolver := net.DefaultResolver

	timer := time.Now()
	addrs, err := resolver.LookupIP(ctx, "ip4", c.hostname)
	elapsed := time.Since(timer)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to lookup IP(s) for host %s: %w", c.hostname, err)
	}
	if len(addrs) == 0 {
		return nil, 0, errors.New("host did not return any IP addresses")
	}
	return addrs, elapsed, nil
}
