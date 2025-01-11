package certcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// lookupHost performs a DNS lookup to resolve the IP addresses for the given hostname.
//
// This function uses a configurable DNS timeout to resolve the hostname to IPv4 addresses.
// It records the duration of the DNS lookup in the provided Metrics.
//
// Steps:
//  1. Create a context with the specified DNS timeout.
//  2. Use the default DNS resolver to resolve the hostname to IPv4 addresses.
//  3. Record the DNS lookup duration in the Metrics.
//  4. Return the list of resolved IP addresses or an error if the lookup fails or no addresses are found.
//
// Parameters:
//   - ctx: A context.Context to manage the DNS lookup timeout.
//   - metrics: A pointer to a Metrics struct to record the DNS lookup duration.
//
// Returns:
//   - A slice of net.IP containing the resolved IP addresses.
//   - An error if the DNS lookup fails or returns no results.
func (c *Checker) lookupHost(ctx context.Context, metrics *Metrics) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Config.DNSTimeout)
	defer cancel()
	resolver := net.DefaultResolver
	resolver.PreferGo = true

	timer := time.Now()
	addrs, err := resolver.LookupIP(ctx, "ip", c.Config.Hostname)
	metrics.DNSLookup = time.Since(timer)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup IP(s) for host %s: %w", c.Config.Hostname, err)
	}
	if len(addrs) == 0 {
		return nil, errors.New("host did not return any IP addresses")
	}
	return addrs, nil
}
