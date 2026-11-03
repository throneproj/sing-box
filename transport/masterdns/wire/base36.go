package wire

import E "github.com/sagernet/sing/common/exceptions"

const base36Alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

var (
	ErrInvalidBase36 = E.New("invalid base36 data")

	// Each 7-byte block becomes 11 digits; a shorter tail of n bytes becomes base36TailChars[n] digits.
	base36TailChars = [8]int{0, 2, 4, 5, 7, 8, 10, 11}
	base36TailBytes = [12]int{0, 0, 1, 0, 2, 3, 0, 4, 5, 0, 6, 7}
	base36Digits    = buildBase36Digits()
)

func Base36Len(n int) int {
	if n <= 0 {
		return 0
	}
	return n/7*11 + base36TailChars[n%7]
}

func AppendBase36(dst []byte, data []byte) []byte {
	for len(data) > 0 {
		blockSize := min(len(data), 7)
		var value uint64
		for _, b := range data[:blockSize] {
			value = value<<8 | uint64(b)
		}
		chars := base36TailChars[blockSize]
		start := len(dst)
		dst = append(dst, make([]byte, chars)...)
		for i := chars - 1; i >= 0; i-- {
			dst[start+i] = base36Alphabet[value%36]
			value /= 36
		}
		data = data[blockSize:]
	}
	return dst
}

// DecodeBase36 accepts either case; a digit group above the byte range of its block is truncated, as in the reference.
func DecodeBase36(dst []byte, data []byte) ([]byte, error) {
	rem := len(data) % 11
	if rem != 0 && base36TailBytes[rem] == 0 {
		return nil, ErrInvalidBase36
	}
	for len(data) > 0 {
		chars := min(len(data), 11)
		var value uint64
		for _, char := range data[:chars] {
			digit := base36Digits[char]
			if digit == 0xFF {
				return nil, ErrInvalidBase36
			}
			value = value*36 + uint64(digit)
		}
		blockSize := base36TailBytes[chars]
		start := len(dst)
		dst = append(dst, make([]byte, blockSize)...)
		for i := blockSize - 1; i >= 0; i-- {
			dst[start+i] = byte(value)
			value >>= 8
		}
		data = data[chars:]
	}
	return dst, nil
}

func buildBase36Digits() [256]byte {
	var digits [256]byte
	for i := range digits {
		digits[i] = 0xFF
	}
	for i := range len(base36Alphabet) {
		char := base36Alphabet[i]
		digits[char] = byte(i)
		if char >= 'a' {
			digits[char-'a'+'A'] = byte(i)
		}
	}
	return digits
}
