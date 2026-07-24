package gocap

import "unicode/utf16"

func fnv1a(str string) uint32 {
	var hash uint32 = 2166136261
	for _, codeUnit := range utf16.Encode([]rune(str)) {
		hash ^= uint32(codeUnit)
		hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24)
	}

	return hash
}

func fnv1aResume(state uint32, str string) uint32 {
	h := state
	for _, codeUnit := range utf16.Encode([]rune(str)) {
		h ^= uint32(codeUnit)
		h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24)
	}

	return h
}

func prng(seed string, length int) string {
	return prngFromHash(fnv1a(seed), length)
}

func prngFromHash(initialHash uint32, length int) string {
	if length <= 0 {
		return ""
	}

	state := initialHash

	const digits = "0123456789abcdef"

	result := make([]byte, 0, length)

	var buf [8]byte

	for len(result) < length {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5

		v := state
		for i := 7; i >= 0; i-- {
			buf[i] = digits[v&0xf]
			v >>= 4
		}

		result = append(result, buf[:]...)
	}

	return string(result[:length])
}
