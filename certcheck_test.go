package certcheck

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	t.Run("New with defaults", func(t *testing.T) {
		config := Config{}
		checker := New(config)
		if checker == nil {
			t.Fatal("failed to get checker instance, New() returned nil")
		}
		if checker.Config.DNSTimeout != DefaultTimeout {
			t.Errorf("expected DNSTimeout to be %s, got %s", DefaultTimeout, checker.Config.DNSTimeout)
		}
		if checker.Config.ConnTimeout != DefaultTimeout {
			t.Errorf("expected ConnTimeout to be %s, got %s", DefaultTimeout, checker.Config.ConnTimeout)
		}
		if checker.Config.Port != DefaultPort {
			t.Errorf("expected Port to be %d, got %d", DefaultPort, checker.Config.Port)
		}
		if checker.Config.DNSRetries != DefaultRetries {
			t.Errorf("expected DNSRetries to be %d, got %d", DefaultRetries, checker.Config.DNSRetries)
		}
	})
	t.Run("New with hostname", func(t *testing.T) {
		config := Config{Hostname: "example.com"}
		checker := New(config)
		if checker == nil {
			t.Fatal("failed to get checker instance, New() returned nil")
		}
		if checker.Config.Hostname != "example.com" {
			t.Errorf("expected Hostname to be %s, got %s", "example.com", checker.Config.Hostname)
		}
		if checker.Config.Certname != "example.com" {
			t.Errorf("expected Certname to be %s, got %s", "example.com", checker.Config.Certname)
		}
	})
	t.Run("New with hostname and certname", func(t *testing.T) {
		config := Config{Hostname: "example.com", Certname: "sub.example.com"}
		checker := New(config)
		if checker == nil {
			t.Fatal("failed to get checker instance, New() returned nil")
		}
		if checker.Config.Hostname != "example.com" {
			t.Errorf("expected Hostname to be %s, got %s", "example.com", checker.Config.Hostname)
		}
		if checker.Config.Certname != "sub.example.com" {
			t.Errorf("expected Certname to be %s, got %s", "sub.example.com", checker.Config.Certname)
		}
	})
}

func TestCheck(t *testing.T) {
	t.Run("Check with valid hostname", func(t *testing.T) {
		checker, ip := defaultChecker(t)
		result, err := checker.Check(context.Background())
		if err != nil {
			t.Fatalf("failed to check certificate: %s", err)
		}
		if result.Addresses[0].String() != ip.String() {
			t.Errorf("expected IP address to be %s, got %s", ip, result.Addresses[0])
		}

	})
	t.Run("Check with empty hostname", func(t *testing.T) {
		config := Config{}
		checker := New(config)
		_, err := checker.Check(nil)
		if err == nil {
			t.Fatal("expected check to fail with empty hostname")
		}
		expErr := "hostname is required"
		if !strings.EqualFold(err.Error(), expErr) {
			t.Errorf("expected error to be %s, got %s", expErr, err)
		}
	})
	t.Run("Check with nil context", func(t *testing.T) {
		config := Config{Hostname: "invalid"}
		checker := New(config)
		_, err := checker.Check(nil)
		if err == nil {
			t.Fatal("expected check to fail with invalid hostname")
		}
		expErr := "context must not be nil"
		if !strings.EqualFold(err.Error(), expErr) {
			t.Errorf("expected error to be %s, got %s", expErr, err)
		}
	})
	t.Run("Check with invalid hostname", func(t *testing.T) {
		config := Config{Hostname: "invalid"}
		checker := New(config)
		_, err := checker.Check(context.Background())
		if err == nil {
			t.Fatal("expected check to fail with invalid hostname")
		}
		expErr := "DNS lookup failed after 3 retries: failed to lookup IP(s) for host invalid: lookup invalid"
		if !strings.Contains(err.Error(), expErr) {
			t.Errorf("expected error to contain %s, got %s", expErr, err)
		}
	})
}

// defaultChecker is a test helper method that returns a Checker and a matching IP address for
// the configured hostname
func defaultChecker(t *testing.T) (*Checker, net.IP) {
	t.Helper()
	hostname := "web.neessen.cloud"
	ip := net.ParseIP("49.12.112.91")
	config := Config{Hostname: hostname, Port: 443}
	checker := New(config)
	return checker, ip
}
