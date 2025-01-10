package certcheck

type Severity int

const (
	SeverityOK Severity = iota
	SeverityWarning
	SeverityCritical
)
