package certcheck

type STARTTLSProto int

const (
	TLSProtoNone STARTTLSProto = iota
	TLSProtoSMTP
	TLSProtoIMAP
)
