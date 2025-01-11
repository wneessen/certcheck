<!--
SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>

SPDX-License-Identifier: MIT
-->

# CheckCert - Certificate Validity Checker

`checkcert` is a CLI tool and Nagios plugin designed to check the validity of SSL/TLS certificates. It evaluates
certificate expiration and alerts based on customizable thresholds. The tool provides detailed metrics for performance
analysis.

## Features

- Validate SSL/TLS certificates for any hostname.
- Support for custom warning and critical thresholds (in days).
- Optional STARTTLS protocol support (`smtp`, `imap`, `ftp`).
- Configurable connection timeout, DNS timeout, and retries.
- Performance metrics for DNS lookup, connection, TLS initialization, and handshake.

## Usage

```shell
$ checkcert -h <hostname> -c <critical_days> -w <warning_days>
```

### Flags

| Flag                     | Description                                                                 | Default      |
|--------------------------|-----------------------------------------------------------------------------|--------------|
| `-h <HOSTNAME>`          | Hostname to connect to                                                     | **Required** |
| `-c <CRITICAL DAYS>`     | Days before expiration to trigger a critical alert                         | 1            |
| `-w <WARNING DAYS>`      | Days before expiration to trigger a warning alert                          | 5            |
| `-p <PORT>`              | Port to connect to                                                        | 443          |
| `-s <STARTTLS PROTOCOL>` | Use STARTTLS protocol instead of HTTPS (`smtp`, `imap`, `ftp`)             | None         |
| `-t <CONNECTION TIMEOUT>`| Timeout for connecting to the server                                       | 5s           |
| `-i <DNS TIMEOUT>`       | Timeout for resolving the IPs of the hostname                              | 5s           |
| `-r <DNS RETRIES>`       | Number of retries if a DNS resolution fails                                | 3            |
| `-m`                     | Verify that certificate name matches the hostname                         | False        |
| `-n <CERTIFICATE NAME>`  | Check for a specific certificate name instead of the hostname              | Hostname     |

## Exit Codes

- `0`: OK - Certificate is valid beyond the warning threshold.
- `1`: WARNING - Certificate is approaching expiration.
- `2`: CRITICAL - Certificate is near expiration or invalid.

## Example

```shell
$ checkcert -h example.com -c 3 -w 7
```

This checks the certificate for `example.com` on port `443` with a warning threshold of 7 days and a critical threshold
of 3 days.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
Developed by Winni Neessen <wn@neessen.dev>.