package tls

// hiddify: helpers for tls_tricks (mixed-case SNI).

import (
	"math/rand"
	"strings"
	"unicode"
)

// randomizeCase returns s with each letter randomly upper/lower-cased. Used for
// the mixed_case_sni trick: many SNI-based DPI filters match case-sensitively,
// so a randomly-cased server name still resolves at the TLS layer but evades the
// filter. Works for both the std and uTLS clients.
func randomizeCase(s string) string {
	var result strings.Builder
	for _, c := range s {
		if rand.Intn(2) == 0 {
			result.WriteRune(unicode.ToUpper(c))
		} else {
			result.WriteRune(unicode.ToLower(c))
		}
	}
	return result.String()
}
