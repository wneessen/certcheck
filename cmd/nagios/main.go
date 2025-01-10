package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/wneessen/certcheck"
)

func main() {
	var certname, hostname, starttls string
	var crit, warn uint
	var connTimeout, dnsTimeout time.Duration
	var retries, port uint
	var starttlsproto certcheck.STARTTLSProto
	var verify bool

	flag.StringVar(&hostname, "h", "", "")
	flag.UintVar(&warn, "w", 5, "")
	flag.UintVar(&crit, "c", 1, "")
	flag.UintVar(&port, "p", 443, "")
	flag.StringVar(&starttls, "s", "", "")
	flag.DurationVar(&connTimeout, "t", 0, "")
	flag.DurationVar(&dnsTimeout, "i", 0, "")
	flag.UintVar(&retries, "r", 3, "")
	flag.BoolVar(&verify, "m", false, "")
	flag.StringVar(&certname, "n", "", "")
	flag.Usage = usage
	flag.Parse()

	if flag.NFlag() == 0 || flag.NArg() != 0 {
		usage()
		_, _ = os.Stderr.WriteString("\n\nMissing flags or arguments\n")
		os.Exit(2)
	}
	if hostname == "" {
		usage()
		_, _ = os.Stderr.WriteString("\n\nHostname is required\n")
		os.Exit(2)
	}
	if port == 0 {
		usage()
		_, _ = os.Stderr.WriteString("\n\nInvalid port\n")
		os.Exit(2)
	}
	if crit > warn {
		usage()
		_, _ = os.Stderr.WriteString("\n\nCritical threshold cannot be higher then warning threshold\n")
		os.Exit(2)
	}
	if starttls != "" {
		switch strings.ToLower(starttls) {
		case "smtp":
			starttlsproto = certcheck.TLSProtoSMTP
		case "imap":
			starttlsproto = certcheck.TLSProtoIMAP
		default:
			_, _ = os.Stderr.WriteString("Unsupported STARTTLS protocol\n")
			usage()
			os.Exit(2)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := certcheck.Config{
		Hostname:    hostname,
		Certname:    certname,
		Port:        port,
		StartTLS:    starttlsproto,
		ConnTimeout: connTimeout,
		DNSTimeout:  dnsTimeout,
		DNSRetries:  retries,
		VerifyCert:  verify,
	}
	checker := certcheck.New(config)
	results, err := checker.Check(ctx)
	if err != nil {
		fail(err, results)
	}

	expDays := time.Until(results.CertExpire).Hours() / 24
	if expDays < float64(crit) {
		results.Severity = certcheck.SeverityCritical
		err = fmt.Errorf("certificate %q on host %s:%d about to expire in %.1f day(s)", checker.Config.Certname,
			checker.Config.Hostname, checker.Config.Port, expDays)
		fail(err, results)
	}
	if expDays < float64(warn) {
		results.Severity = certcheck.SeverityWarning
		err = fmt.Errorf("certificate %q on host %s:%d about to expire in %.1f day(s)", checker.Config.Certname,
			checker.Config.Hostname, checker.Config.Port, expDays)
		fail(err, results)
	}

	fmt.Printf("OK: certificate for %q on host %s:%d still valid, certificate will expire in %.1f days %s\n",
		checker.Config.Certname, checker.Config.Hostname, checker.Config.Port, expDays, metrics(results.Metrics))
	os.Exit(0)
}

func metrics(metrics *certcheck.Metrics) string {
	var builder strings.Builder
	builder.WriteString("(")

	if metrics.DNSLookup != 0 {
		builder.WriteString(fmt.Sprintf("DNS lookup: %s, ", metrics.DNSLookup))
	}
	if metrics.ConnTime != 0 {
		builder.WriteString(fmt.Sprintf("Connect time: %s, ", metrics.ConnTime))
	}
	if metrics.TLSInit != 0 {
		builder.WriteString(fmt.Sprintf("TLS init: %s, ", metrics.TLSInit))
	}
	if metrics.TLSHandshake != 0 {
		builder.WriteString(fmt.Sprintf("TLS handshake: %s, ", metrics.TLSHandshake))
	}

	result := builder.String()
	if strings.HasSuffix(result, ", ") {
		result = result[:len(result)-2]
	}

	return result + ")"
}

func fail(err error, results certcheck.Result) {
	switch results.Severity {
	case certcheck.SeverityWarning:
		fmt.Printf("WARNING: %s %s\n", err, metrics(results.Metrics))
		os.Exit(1)
	case certcheck.SeverityCritical:
		fmt.Printf("CRITICAL: %s %s\n", err, metrics(results.Metrics))
		os.Exit(2)
	default:
	}
}

// usage is used by the flag package to display the CLI usage message
func usage() {
	const usage = `checkcert - a Nagios plugin to check certificate validity
Copyright (c) 2021-2025 by Winni Neessen (MIT licensed)

Usage: checkcert -h <hostname> -c <critical> -w <warning> 
                 [-p <port> -s <starttls proto> -t <timeout> -i <dnstimeout> -r <retries> -m -n <certname>]"

Flags:
	-h <HOSTNAME>			Hostname to connect to
	-c <CRITICAL DAYS>		Number of days left of the certificate validity that triggers a CRITICAL alert
	-w <WARNING DAYS>		Number of days left of the certificate validity that triggers a WARANING alert
	-p <PORT>				Port to connect to (Default: 443)
	-s <STARTTLS PROTOCOL>	Use STARTTLS protocol instead of HTTPS (Supported protocols: smtp, imap)
	-t <CONNECTION TIMEOUT>	Timeout for connecting to the server (Default: 5s)
	-i <DNS TIMEOUT>		Timeout for resolving the IPs of the hostname (Default: 5s)
	-r <DNS RETRIES>		Number of re-tries if a DNS resolution fails (Default: 3)
	-m						Verify that certificate name matches the certificate
	-n <CERTIFICATE NAME>	Check for a different certificate name then the hostname (Default: <HOSTNAME>)`

	_, _ = os.Stderr.WriteString(usage + "\n\n")
}
