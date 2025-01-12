// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package certcheck

// Severity represents the level of importance or criticality of a certificate check result.
//
// This type is used to classify the outcome of a check into categories such as OK, Warning, or Critical.
type Severity int

// Severity levels for the result of a certificate check.
const (
	// SeverityWarning indicates that the check passed with some warnings or potential issues.
	SeverityWarning = iota + 1

	// SeverityCritical indicates that the check failed due to critical issues.
	SeverityCritical
)
