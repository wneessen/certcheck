package certcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

func (c *Checker) lookupHost(ctx context.Context, metrics *Metrics) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Config.DNSTimeout)
	defer cancel()
	resolver := net.DefaultResolver

	timer := time.Now()
	addrs, err := resolver.LookupIP(ctx, "ip4", c.Config.Hostname)
	metrics.DNSLookup = time.Since(timer)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup IP(s) for host %s: %w", c.Config.Hostname, err)
	}
	if len(addrs) == 0 {
		return nil, errors.New("host did not return any IP addresses")
	}
	return addrs, nil
}
