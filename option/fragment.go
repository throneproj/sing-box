package option

// hiddify: TCP-level TLS ClientHello fragmentation (see common/dialer/fragment.go).
type TLSFragmentOptions struct {
	Enabled bool   `json:"enabled,omitempty"`
	Size    string `json:"size,omitempty"`   // Fragment size in bytes
	Sleep   string `json:"sleep,omitempty"`  // Time to sleep between sending the fragments in milliseconds
	Method  string `json:"method,omitempty"` // Whether to fragment only clientHello or a range of TCP packets. Valid options: ['tlsHello', 'range']
	Range   string `json:"range,omitempty"`  // Range of TCP packets to fragment when method is 'range'
}
