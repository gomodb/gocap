package gocap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
)

var jwtHeaderB64 = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

func randomHex(bytesCount int) (string, error) {
	if bytesCount <= 0 {
		return "", nil
	}

	buf := make([]byte, bytesCount)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}

	return hex.EncodeToString(buf), nil
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func hmacSha256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)

	return m.Sum(nil)
}

func timingSafeEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}

func deriveKey(secret []byte, info string) []byte {
	return hmacSha256(secret, []byte(info))
}

// encryptGcm encrypts data using AES-256-GCM with a key derived from secret via HMAC-SHA256(info).
// Returns base64url(iv + tag + ciphertext).
func encryptGcm(data any, secret []byte, info ...string) (string, error) {
	infoStr := "cap:enc-v1"
	if len(info) > 0 {
		infoStr = info[0]
	}

	key := deriveKey(secret, infoStr)

	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	encrypted := aead.Seal(nil, iv, plaintext, nil)
	tag := encrypted[len(encrypted)-16:]
	ciphertext := encrypted[:len(encrypted)-16]
	out := make([]byte, 0, len(iv)+16+len(ciphertext))
	out = append(out, iv...)
	out = append(out, tag...)
	out = append(out, ciphertext...)

	return base64.RawURLEncoding.EncodeToString(out), nil
}

// decryptGcm decrypts a blob created by encryptGcm.
func decryptGcm(blob string, secret []byte, info ...string) map[string]any {
	infoStr := "cap:enc-v1"
	if len(info) > 0 {
		infoStr = info[0]
	}

	buf, err := base64.RawURLEncoding.DecodeString(blob)
	if err != nil || len(buf) < 28 {
		return nil
	}

	iv := buf[:12]
	tag := buf[12:28]
	ciphertext := buf[28:]
	key := deriveKey(secret, infoStr)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}

	nonce := make([]byte, 12)
	copy(nonce, iv)

	encWithTag := make([]byte, 0, len(ciphertext)+len(tag))
	encWithTag = append(encWithTag, ciphertext...)
	encWithTag = append(encWithTag, tag...)

	plaintext, err := aead.Open(nil, nonce, encWithTag, nil)
	if err != nil {
		return nil
	}

	var result map[string]any
	if err := json.Unmarshal(plaintext, &result); err != nil {
		return nil
	}

	return result
}

// decryptGcmRaw decrypts and returns raw bytes, used internally for typed structs.
func decryptGcmRaw(blob string, secret []byte, info ...string) ([]byte, bool) {
	infoStr := "cap:enc-v1"
	if len(info) > 0 {
		infoStr = info[0]
	}

	buf, err := base64.RawURLEncoding.DecodeString(blob)
	if err != nil || len(buf) < 28 {
		return nil, false
	}

	iv := buf[:12]
	tag := buf[12:28]
	ciphertext := buf[28:]
	key := deriveKey(secret, infoStr)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false
	}

	nonce := make([]byte, 12)
	copy(nonce, iv)

	encWithTag := make([]byte, 0, len(ciphertext)+len(tag))
	encWithTag = append(encWithTag, ciphertext...)
	encWithTag = append(encWithTag, tag...)

	plaintext, err := aead.Open(nil, nonce, encWithTag, nil)
	if err != nil {
		return nil, false
	}

	return plaintext, true
}

func b64url(input []byte) string {
	return base64.RawURLEncoding.EncodeToString(input)
}

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func jwtSign(payloadOrJSON any, secret []byte) string {
	var jsonBytes []byte

	switch v := payloadOrJSON.(type) {
	case string:
		jsonBytes = []byte(v)
	case []byte:
		jsonBytes = v
	default:
		jsonBytes, _ = json.Marshal(v)
	}

	body := b64url(jsonBytes)
	sigInput := jwtHeaderB64 + "." + body
	sig := hmacSha256(secret, []byte(sigInput))

	return sigInput + "." + b64url(sig)
}

func jwtVerify(token string, secret []byte) map[string]any {
	if token == "" {
		return nil
	}

	firstDot := -1
	lastDot := -1

	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			if firstDot == -1 {
				firstDot = i
			}

			lastDot = i
		}
	}

	if firstDot < 1 || lastDot == firstDot {
		return nil
	}

	if token[firstDot+1:lastDot] == "" || token[lastDot+1:] == "" {
		return nil
	}

	sigInput := token[:lastDot]
	expected := hmacSha256(secret, []byte(sigInput))

	actual, err := b64urlDecode(token[lastDot+1:])
	if err != nil || !timingSafeEqual(expected, actual) {
		return nil
	}

	decoded, err := b64urlDecode(token[firstDot+1 : lastDot])
	if err != nil {
		return nil
	}

	var payload map[string]any
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return nil
	}

	return payload
}

func jwtSigHex(token string) string {
	if token == "" {
		return ""
	}

	lastDot := -1

	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			lastDot = i
		}
	}

	if lastDot == -1 {
		return ""
	}

	sig, err := b64urlDecode(token[lastDot+1:])
	if err != nil {
		return ""
	}

	return hex.EncodeToString(sig)
}
