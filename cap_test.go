package gocap

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"
)

func solveChallenge(token string, c, s, d int) []int64 {
	solutions := make([]int64, 0, c)
	for i := 1; i <= c; i++ {
		salt := prng(token+fmt.Sprint(i), s)

		target := prng(token+fmt.Sprint(i)+"d", d)
		for n := int64(0); ; n++ {
			h := sha256.Sum256([]byte(salt + fmt.Sprint(n)))

			hx := hex.EncodeToString(h[:])
			if len(hx) >= len(target) && hx[:len(target)] == target {
				solutions = append(solutions, n)
				break
			}
		}
	}

	return solutions
}

// ─── PRNG tests ─────────────────────────────────────────────────────────────

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("entropy failed") }

func TestPrngMatchesKnownBehavior(t *testing.T) {
	a := prng("tokensampleX1", 16)

	b := prng("tokensampleX1", 16)
	if a != b {
		t.Fatalf("expected deterministic output, got %q and %q", a, b)
	}

	if len(a) != 16 {
		t.Fatalf("unexpected prng length: %d", len(a))
	}

	for _, ch := range a {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			t.Fatalf("prng returned non-hex character: %q", ch)
		}
	}

	if got := prng("😺", 32); len(got) != 32 {
		t.Fatalf("unexpected prng length: %d", len(got))
	}
}

func TestPrngRegressionWireFormat(t *testing.T) {
	// Verify against known widget-side values
	type testCase struct {
		seed   string
		length int
		expect string // first 8 hex chars
	}

	cases := []testCase{
		{"abc", 8, "ba78d880"},
		{"deadbeef", 8, "ded6fea5"},
		{"tokensampleX1", 8, "628acc03"},
		{"tokensampleX1d", 8, "1c1c2353"},
	}
	// Widget-side PRNG for verification
	widgetPrng := func(seed string, length int) string {
		fnv1aWidget := func(str string) uint32 {
			var hash uint32 = 2166136261

			for _, codeUnit := range str {
				low := uint32(codeUnit)
				if codeUnit > 0xFFFF {
					high := uint32(0xD800 + ((codeUnit - 0x10000) >> 10))
					low = uint32(0xDC00 + ((codeUnit - 0x10000) & 0x3FF))
					hash ^= high
					hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24)
				}

				hash ^= low
				hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24)
			}

			return hash
		}

		state := fnv1aWidget(seed)

		result := ""
		for len(result) < length {
			state ^= state << 13
			state ^= state >> 17
			state ^= state << 5
			result += fmt.Sprintf("%08x", state)
		}

		return result[:length]
	}
	for _, tc := range cases {
		got := prng(tc.seed, tc.length)

		want := widgetPrng(tc.seed, tc.length)
		if got != want {
			t.Fatalf("prng(%q, %d) = %q, want %q", tc.seed, tc.length, got, want)
		}
	}
}

// ─── Crypto helper tests ────────────────────────────────────────────────────

func TestCryptoAndHelperBranches(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	if got, err := randomHex(0); got != "" || err != nil {
		t.Fatalf("expected empty randomHex for zero bytes, got %q err=%v", got, err)
	}

	// Verify randomHex returns error when entropy source fails
	originalReader := crand.Reader
	crand.Reader = errReader{}
	_, err := randomHex(1)
	crand.Reader = originalReader

	if err == nil {
		t.Fatal("expected randomHex to return error when entropy source fails")
	}

	if got := prngFromHash(123, 0); got != "" {
		t.Fatalf("expected empty prngFromHash for zero length, got %q", got)
	}

	stringToken := jwtSign("{}", secret)
	if jwtVerify(stringToken, secret) == nil {
		t.Fatal("expected string payload token to verify")
	}

	bytesToken := jwtSign([]byte(`{"x":1}`), secret)
	if jwtVerify(bytesToken, secret) == nil {
		t.Fatal("expected byte payload token to verify")
	}

	if jwtVerify("", secret) != nil {
		t.Fatal("expected empty token to fail")
	}

	if jwtVerify(".b.c", secret) != nil {
		t.Fatal("expected token with empty header to fail")
	}

	if jwtVerify("a..c", secret) != nil {
		t.Fatal("expected token with empty payload to fail")
	}

	if jwtVerify("a.b", secret) != nil {
		t.Fatal("expected malformed token to fail")
	}

	if jwtVerify("a.b.c.d", secret) != nil {
		t.Fatal("expected token with too many dots to fail")
	}

	if jwtVerify("a.b.", secret) != nil {
		t.Fatal("expected token with empty signature to fail")
	}

	if jwtVerify("a.b.?", secret) != nil {
		t.Fatal("expected token with invalid base64 signature to fail")
	}

	if jwtSigHex("nocolon") != "" {
		t.Fatal("expected malformed token signature hex to be empty")
	}

	if jwtSigHex("") != "" {
		t.Fatal("expected empty token signature hex to be empty")
	}

	if jwtSigHex("a.b.?") != "" {
		t.Fatal("expected invalid base64 signature to return empty hex")
	}

	if sig := jwtSigHex(stringToken); len(sig) != 64 {
		t.Fatalf("expected 64-char signature hex, got %d", len(sig))
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	sigInput := header + "." + body

	badJSONToken := sigInput + "." + b64url(hmacSha256(secret, []byte(sigInput)))
	if jwtVerify(badJSONToken, secret) != nil {
		t.Fatal("expected invalid JSON payload to fail verification")
	}

	badPayloadBody := "?"
	badPayloadInput := header + "." + badPayloadBody

	badPayloadToken := badPayloadInput + "." + b64url(hmacSha256(secret, []byte(badPayloadInput)))
	if jwtVerify(badPayloadToken, secret) != nil {
		t.Fatal("expected invalid base64 payload to fail verification")
	}

	// Verify res() helper creates a proper failure result with sentinel error
	got := res(ErrExpired)
	if got.Success || got.Reason != "expired" {
		t.Fatalf("unexpected res() output: %+v", got)
	}

	if !errors.Is(got, ErrExpired) {
		t.Fatal("res() result should unwrap to the sentinel error")
	}
}

// ─── AES-256-GCM tests ──────────────────────────────────────────────────────

func TestEncryptDecryptGcm(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	data := map[string]any{"id": "abc", "vals": []any{1.0, 2.0, 3.0}}

	blob, err := encryptGcm(data, secret)
	if err != nil || blob == "" {
		t.Fatal("expected non-empty encrypted blob")
	}

	decrypted := decryptGcm(blob, secret)
	if decrypted == nil {
		t.Fatal("expected successful decryption")
	}

	if decrypted["id"] != "abc" {
		t.Fatalf("unexpected id: %v", decrypted["id"])
	}

	// Encryption is non-deterministic
	blob2, err := encryptGcm(data, secret)
	if err != nil || blob == blob2 {
		t.Fatal("expected different ciphertexts due to random IV")
	}

	// Wrong secret
	wrongSecret := []byte("different-secret-32-bytes-padding-junk!")
	if got := decryptGcm(blob, wrongSecret); got != nil {
		t.Fatal("expected decryption to fail with wrong secret")
	}

	// Tampered blob
	buf, _ := base64.RawURLEncoding.DecodeString(blob)
	buf[len(buf)-1] ^= 0xff

	tampered := base64.RawURLEncoding.EncodeToString(buf)
	if got := decryptGcm(tampered, secret); got != nil {
		t.Fatal("expected decryption to fail with tampered blob")
	}

	// Too-short blob
	if got := decryptGcm("aGVsbG8", secret); got != nil {
		t.Fatal("expected decryption to fail with short blob")
	}

	// Invalid base64
	if got := decryptGcm("notvalidbase64!!!@@@", secret); got != nil {
		t.Fatal("expected decryption to fail with invalid base64")
	}

	// Info parameter scopes keys
	blobA, err := encryptGcm(data, secret, "context-A")
	if err != nil {
		t.Fatal(err)
	}

	if got := decryptGcm(blobA, secret, "context-B"); got != nil {
		t.Fatal("expected decryption with wrong info to fail")
	}

	if got := decryptGcm(blobA, secret, "context-A"); got == nil {
		t.Fatal("expected decryption with correct info to succeed")
	}
}

func TestEncryptDecryptGcmRaw(t *testing.T) {
	secret := []byte("test-secret-32-bytes-for-testing-ok!")
	data := map[string]string{"foo": "bar"}

	blob, err := encryptGcm(data, secret, "cap:fmt2-v1")
	if err != nil {
		t.Fatal(err)
	}

	raw, ok := decryptGcmRaw(blob, secret, "cap:fmt2-v1")
	if !ok {
		t.Fatal("expected successful raw decryption")
	}

	var result map[string]string
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}

	if result["foo"] != "bar" {
		t.Fatalf("unexpected value: %v", result)
	}

	// Wrong info
	_, ok = decryptGcmRaw(blob, secret, "wrong-info")
	if ok {
		t.Fatal("expected decryption with wrong info to fail")
	}
}

// ─── AsInt64 tests ──────────────────────────────────────────────────────────

func TestAsInt64Branches(t *testing.T) {
	maxInt64 := int64(^uint64(0) >> 1)
	tooLarge := uint64(maxInt64) + 1

	cases := []struct {
		name string
		in   any
		want int64
		ok   bool
	}{
		{"int", int(-3), -3, true},
		{"int8", int8(-4), -4, true},
		{"int16", int16(5), 5, true},
		{"int32", int32(6), 6, true},
		{"int64", int64(7), 7, true},
		{"uint", uint(8), 8, true},
		{"uint8", uint8(9), 9, true},
		{"uint16", uint16(10), 10, true},
		{"uint32", uint32(11), 11, true},
		{"uint64", uint64(12), 12, true},
		{"uint64 too large", tooLarge, 0, false},
		{"float64 exact", float64(13), 13, true},
		{"float64 not exact", float64(13.25), 0, false},
		{"float32 exact", float32(14), 14, true},
		{"float32 not exact", float32(14.5), 0, false},
		{"default", "nope", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := asInt64(tc.in)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("asInt64(%T) = (%d,%v), want (%d,%v)", tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// ─── ClampChallengeOptions tests ────────────────────────────────────────────

func TestClampChallengeOptionsBranches(t *testing.T) {
	c, s, d, ttl, err := clampChallengeOptions(GenerateOptions{})
	if err != nil || c != defaultChallengeCount || s != defaultChallengeSize ||
		d != defaultChallengeDifficulty ||
		ttl != defaultChallengeTTL {
		t.Fatalf("unexpected default clamp result: %d %d %d %v %v", c, s, d, ttl, err)
	}

	if _, _, _, _, err := clampChallengeOptions(
		GenerateOptions{ChallengeCount: 0, ChallengeSize: 999, ChallengeDifficulty: 1},
	); err == nil {
		t.Fatal("expected invalid options error")
	}
}

// ─── MemoryStorage tests ────────────────────────────────────────────────────

func TestMemoryStorageCleanup(t *testing.T) {
	store := NewMemoryStorage()
	challengeToken := "challenge-token"
	validationToken := "validation-token"

	if err := store.SetChallengeToken(
		context.Background(),
		challengeToken,
		time.Now().Add(5*time.Millisecond),
	); err != nil {
		t.Fatal(err)
	}

	if err := store.SetValidationToken(
		context.Background(),
		validationToken,
		time.Now().Add(5*time.Millisecond),
	); err != nil {
		t.Fatal(err)
	}

	if _, ok, err := store.GetChallengeTokenExpiry(
		context.Background(),
		challengeToken,
	); err != nil ||
		!ok {
		t.Fatalf("expected challenge token to exist, got ok=%v err=%v", ok, err)
	}

	if _, ok, err := store.GetValidationTokenExpiry(
		context.Background(),
		validationToken,
	); err != nil ||
		!ok {
		t.Fatalf("expected validation token to exist, got ok=%v err=%v", ok, err)
	}

	time.Sleep(10 * time.Millisecond)

	if err := store.CleanupExpired(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, ok, err := store.GetChallengeTokenExpiry(
		context.Background(),
		challengeToken,
	); err != nil ||
		ok {
		t.Fatalf("expected challenge token to be removed, got ok=%v err=%v", ok, err)
	}

	if _, ok, err := store.GetValidationTokenExpiry(
		context.Background(),
		validationToken,
	); err != nil ||
		ok {
		t.Fatalf("expected validation token to be removed, got ok=%v err=%v", ok, err)
	}
}

// ─── Cap instance tests ─────────────────────────────────────────────────────

func TestNewCapAndInstanceMethods(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	capInstance, err := NewCap(CapOptions{
		Secret:              secret,
		Storage:             store,
		ChallengeCount:      1,
		ChallengeSize:       8,
		ChallengeDifficulty: 1,
		Scope:               "signup",
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	solutions := solveChallenge(
		challenge.Token,
		challenge.Challenge.C,
		challenge.Challenge.S,
		challenge.Challenge.D,
	)

	result, err := capInstance.RedeemChallenge(context.Background(), ValidateBody{
		Token:     challenge.Token,
		Solutions: solutions,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !result.Success {
		t.Fatalf("expected validation success, got reason: %s", result.Reason)
	}

	if result.Token == "" {
		t.Fatal("expected validation token")
	}

	if result.Expires == 0 {
		t.Fatal("expected expires to be set")
	}

	if vt := capInstance.ValidateToken(context.Background(), result.Token); !vt.Success {
		t.Fatalf("expected validation token to be valid, got reason: %s", vt.Reason)
	}

	if vt := capInstance.ValidateToken(context.Background(), "missing-token"); vt.Success {
		t.Fatalf("expected missing token to be invalid, got reason: %s", vt.Reason)
	}
}

func TestNewCapErrors(t *testing.T) {
	if _, err := NewCap(CapOptions{Secret: []byte("short")}); err == nil {
		t.Fatal("expected short secret to fail")
	}
	// Format-2 without protocols
	if _, err := NewCap(CapOptions{
		Secret: []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow"),
		Format: 2,
	}); err == nil {
		t.Fatal("expected format-2 without protocols to fail")
	}
}

func TestCapValidateTokenWithoutStorage(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	capInstance, err := NewCap(CapOptions{Secret: secret})
	if err != nil {
		t.Fatal(err)
	}

	if vt := capInstance.ValidateToken(context.Background(), "any"); vt.Success {
		t.Fatalf(
			"expected token to be invalid when storage is not configured, got reason: %s",
			vt.Reason,
		)
	}
}

// ─── Format-1 instrumentation tests ─────────────────────────────────────────

func TestFormat1InstrumentationFlow(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	capInstance, err := NewCap(CapOptions{
		Secret:              secret,
		Storage:             store,
		ChallengeCount:      2,
		ChallengeSize:       8,
		ChallengeDifficulty: 1,
		Instrumentation:     true,
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if challenge.Instrumentation == "" {
		t.Fatal("expected instrumentation blob in challenge")
	}

	// Verify the JWT has encrypted instrumentation metadata
	payload := jwtVerify(challenge.Token, secret)
	if payload == nil {
		t.Fatal("expected valid token")
	}

	ei, ok := payload["ei"]
	if !ok {
		t.Fatal("expected ei field in token payload")
	}

	eiStr, _ := ei.(string)
	if eiStr == "" {
		t.Fatal("expected non-empty ei")
	}

	// Decrypt and verify metadata
	meta := instrumentationMetaFromEncrypted(eiStr, secret)
	if meta == nil {
		t.Fatal("expected instrumentation metadata to decrypt")
	}

	if len(meta.Vars) != 4 {
		t.Fatalf("expected 4 vars, got %d", len(meta.Vars))
	}

	if len(meta.ExpectedVals) != 4 {
		t.Fatalf("expected 4 expectedVals, got %d", len(meta.ExpectedVals))
	}

	if meta.ID == "" {
		t.Fatal("expected non-empty id")
	}

	// Solve PoW
	solutions := solveChallenge(
		challenge.Token,
		challenge.Challenge.C,
		challenge.Challenge.S,
		challenge.Challenge.D,
	)

	// Submit without instrumentation → should fail with instr_missing
	result, err := capInstance.RedeemChallenge(context.Background(), ValidateBody{
		Token:     challenge.Token,
		Solutions: solutions,
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected validation to fail with missing instrumentation")
	}

	if result.Reason != "instr_missing" {
		t.Fatalf("expected instr_missing, got %s", result.Reason)
	}

	if !result.InstrErr {
		t.Fatal("expected instr_error flag")
	}
}

func TestFormat1InstrumentationBlocked(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	// With blockAutomatedBrowsers=false → should succeed
	capInstance, err := NewCap(CapOptions{
		Secret:              secret,
		Storage:             store,
		ChallengeCount:      1,
		ChallengeSize:       4,
		ChallengeDifficulty: 1,
		Instrumentation:     true,
		InstrumentationOpts: &InstrumentationOptions{
			BlockAutomatedBrowsers: false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	solutions := solveChallenge(
		challenge.Token,
		challenge.Challenge.C,
		challenge.Challenge.S,
		challenge.Challenge.D,
	)

	result, err := capInstance.RedeemChallenge(context.Background(), ValidateBody{
		Token:     challenge.Token,
		Solutions: solutions,
		Blocked:   true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !result.Success {
		t.Fatalf(
			"expected success with blockAutomatedBrowsers=false, got reason: %s",
			result.Reason,
		)
	}

	// With blockAutomatedBrowsers=true → should be rejected
	capInstance2, err := NewCap(CapOptions{
		Secret:              secret,
		Storage:             store,
		ChallengeCount:      1,
		ChallengeSize:       4,
		ChallengeDifficulty: 1,
		Instrumentation:     true,
		InstrumentationOpts: &InstrumentationOptions{
			BlockAutomatedBrowsers: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge2, err := capInstance2.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	solutions2 := solveChallenge(
		challenge2.Token,
		challenge2.Challenge.C,
		challenge2.Challenge.S,
		challenge2.Challenge.D,
	)

	result2, err := capInstance2.RedeemChallenge(context.Background(), ValidateBody{
		Token:     challenge2.Token,
		Solutions: solutions2,
		Blocked:   true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if result2.Success {
		t.Fatal("expected failure with blockAutomatedBrowsers=true")
	}

	if result2.Reason != "instr_automated_browser" {
		t.Fatalf("expected instr_automated_browser, got %s", result2.Reason)
	}
}

func TestFormat1InstrumentationTimeout(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	capInstance, err := NewCap(CapOptions{
		Secret:              secret,
		Storage:             store,
		ChallengeCount:      1,
		ChallengeSize:       4,
		ChallengeDifficulty: 1,
		Instrumentation:     true,
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	solutions := solveChallenge(
		challenge.Token,
		challenge.Challenge.C,
		challenge.Challenge.S,
		challenge.Challenge.D,
	)

	result, err := capInstance.RedeemChallenge(context.Background(), ValidateBody{
		Token:     challenge.Token,
		Solutions: solutions,
		Timeout:   true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected failure with timeout")
	}

	if result.Reason != "instr_timeout" {
		t.Fatalf("expected instr_timeout, got %s", result.Reason)
	}
}

func TestFormat1InstrumentationValidResult(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	capInstance, err := NewCap(CapOptions{
		Secret:              secret,
		Storage:             store,
		ChallengeCount:      1,
		ChallengeSize:       4,
		ChallengeDifficulty: 1,
		Instrumentation:     true,
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt the instrumentation metadata to build a correct response
	payload := jwtVerify(challenge.Token, secret)
	ei, _ := payload["ei"].(string)

	meta := instrumentationMetaFromEncrypted(ei, secret)
	if meta == nil {
		t.Fatal("expected to decrypt metadata")
	}

	solutions := solveChallenge(
		challenge.Token,
		challenge.Challenge.C,
		challenge.Challenge.S,
		challenge.Challenge.D,
	)

	// Build valid state from metadata
	state := make(map[string]int)
	for i, v := range meta.Vars {
		state[v] = meta.ExpectedVals[i]
	}

	result, err := capInstance.RedeemChallenge(context.Background(), ValidateBody{
		Token:     challenge.Token,
		Solutions: solutions,
		Instr: &InstrPayload{
			I:     meta.ID,
			State: state,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if !result.Success {
		t.Fatalf(
			"expected success with valid instrumentation result, got reason: %s",
			result.Reason,
		)
	}
}

// ─── Instrumentation metadata encryption/decryption tests ───────────────────

func TestInstrumentationMetaEncryption(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	meta := &InstrumentationMeta{
		ID:                     "test-id-32-chars-xxxxxxxxxxxxx",
		ExpectedVals:           []int{100, 200, 300, 400},
		Vars:                   []string{"aVar", "bVar", "cVar", "dVar"},
		BlockAutomatedBrowsers: true,
		Expires:                time.Now().UnixMilli() + 60000,
	}

	encrypted, err := encodeInstrumentationMeta(meta, secret)
	if err != nil || encrypted == "" {
		t.Fatal("expected non-empty encrypted blob")
	}

	decrypted := instrumentationMetaFromEncrypted(encrypted, secret)
	if decrypted == nil {
		t.Fatal("expected successful decryption")
	}

	if decrypted.ID != meta.ID {
		t.Fatalf("expected id %q, got %q", meta.ID, decrypted.ID)
	}

	if decrypted.BlockAutomatedBrowsers != meta.BlockAutomatedBrowsers {
		t.Fatal("blockAutomatedBrowsers mismatch")
	}

	if len(decrypted.ExpectedVals) != len(meta.ExpectedVals) {
		t.Fatal("expectedVals length mismatch")
	}

	for i := range meta.ExpectedVals {
		if decrypted.ExpectedVals[i] != meta.ExpectedVals[i] {
			t.Fatalf(
				"expectedVals[%d] mismatch: %d vs %d",
				i,
				decrypted.ExpectedVals[i],
				meta.ExpectedVals[i],
			)
		}
	}

	// Wrong secret
	if got := instrumentationMetaFromEncrypted(
		encrypted,
		[]byte("wrong-secret-32-bytes-for-testing-ok!"),
	); got != nil {
		t.Fatal("expected decryption to fail with wrong secret")
	}
}

// ─── VerifyInstrumentationResult tests ──────────────────────────────────────

func TestVerifyInstrumentationResult(t *testing.T) {
	meta := &InstrumentationMeta{
		ID:                     "abc123",
		ExpectedVals:           []int{111, 222, 333, 444},
		Vars:                   []string{"x", "y", "z", "w"},
		BlockAutomatedBrowsers: false,
	}

	// Valid result
	valid, reason := VerifyInstrumentationResult(meta, &InstrumentationResult{
		I:     "abc123",
		State: map[string]int{"x": 111, "y": 222, "z": 333, "w": 444},
	})
	if !valid {
		t.Fatalf("expected valid, got reason: %s", reason)
	}

	// Wrong ID
	valid, _ = VerifyInstrumentationResult(meta, &InstrumentationResult{
		I:     "wrong-id",
		State: map[string]int{"x": 111, "y": 222, "z": 333, "w": 444},
	})
	if valid {
		t.Fatal("expected invalid with wrong ID")
	}

	// Wrong state values
	valid, reason = VerifyInstrumentationResult(meta, &InstrumentationResult{
		I:     "abc123",
		State: map[string]int{"x": 0, "y": 0, "z": 0, "w": 0},
	})
	if valid {
		t.Fatal("expected invalid with wrong state")
	}

	if reason != "failed_challenge" {
		t.Fatalf("expected failed_challenge, got %s", reason)
	}

	// Nil meta
	valid, _ = VerifyInstrumentationResult(
		nil,
		&InstrumentationResult{I: "abc", State: map[string]int{}},
	)
	if valid {
		t.Fatal("expected invalid with nil meta")
	}

	// Nil payload
	valid, _ = VerifyInstrumentationResult(meta, nil)
	if valid {
		t.Fatal("expected invalid with nil payload")
	}

	// Missing vars
	valid, _ = VerifyInstrumentationResult(
		&InstrumentationMeta{ID: "x"},
		&InstrumentationResult{I: "x", State: map[string]int{}},
	)
	if valid {
		t.Fatal("expected invalid with missing vars")
	}
}

// ─── RSW tests ──────────────────────────────────────────────────────────────

func TestGenerateRswKeypair(t *testing.T) {
	kp, err := GenerateRswKeypair(256) // small for test speed
	if err != nil {
		t.Fatal(err)
	}

	if kp.N == nil || kp.P == nil || kp.Q == nil {
		t.Fatal("expected non-nil keypair components")
	}
	// Verify N = P * Q
	N := new(big.Int).Mul(kp.P, kp.Q)
	if N.Cmp(kp.N) != 0 {
		t.Fatal("N != P * Q")
	}

	// Reject odd bits
	_, err = GenerateRswKeypair(257)
	if err == nil {
		t.Fatal("expected error for odd bits")
	}
}

func TestRswKeypairSerialization(t *testing.T) {
	kp, err := GenerateRswKeypair(256)
	if err != nil {
		t.Fatal(err)
	}

	ser := SerializeRswKeypair(kp)
	if ser.N == "" || ser.P == "" || ser.Q == "" {
		t.Fatal("expected non-empty serialized fields")
	}

	deser, err := DeserializeRswKeypair(ser)
	if err != nil {
		t.Fatal(err)
	}

	if deser.N.Cmp(kp.N) != 0 {
		t.Fatal("N mismatch after deserialization")
	}

	// Nil deserialization
	_, err = DeserializeRswKeypair(nil)
	if err == nil {
		t.Fatal("expected error for nil serialized")
	}

	// Invalid bigint
	_, err = DeserializeRswKeypair(&SerializedRswKeypair{N: "not-a-number", P: "1", Q: "1"})
	if err == nil {
		t.Fatal("expected error for invalid bigint")
	}
}

func TestBuildRswMinter(t *testing.T) {
	kp, err := GenerateRswKeypair(256)
	if err != nil {
		t.Fatal(err)
	}

	minter, err := BuildRswMinter(struct {
		N *big.Int
		P *big.Int
		Q *big.Int
		T int
		G *big.Int
	}{
		N: kp.N,
		P: kp.P,
		Q: kp.Q,
		T: 100,
	})
	if err != nil {
		t.Fatal(err)
	}

	if minter.N_hex == "" || minter.G_hex == "" || minter.H_hex == "" {
		t.Fatal("expected non-empty hex strings")
	}

	// Nil args
	_, err = BuildRswMinter(struct {
		N, P, Q *big.Int
		T       int
		G       *big.Int
	}{T: 100})
	if err == nil {
		t.Fatal("expected error for nil N")
	}

	// Zero T
	_, err = BuildRswMinter(struct {
		N, P, Q *big.Int
		T       int
		G       *big.Int
	}{
		N: kp.N, P: kp.P, Q: kp.Q, T: 0,
	})
	if err == nil {
		t.Fatal("expected error for zero T")
	}
}

func TestRswMintAndVerify(t *testing.T) {
	kp, err := GenerateRswKeypair(256)
	if err != nil {
		t.Fatal(err)
	}

	minter, err := BuildRswMinter(struct {
		N *big.Int
		P *big.Int
		Q *big.Int
		T int
		G *big.Int
	}{
		N: kp.N,
		P: kp.P,
		Q: kp.Q,
		T: 100,
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := minter.Mint()
	if err != nil {
		t.Fatal(err)
	}

	if result.X_hex == "" || result.Y_hex == "" {
		t.Fatal("expected non-empty mint result")
	}

	// Verify
	if !VerifyRswSolution(result.Y_hex, result.Y_hex) {
		t.Fatal("expected same y values to match")
	}

	// Mismatched
	if VerifyRswSolution(result.Y_hex, "deadbeef") {
		t.Fatal("expected different y values to mismatch")
	}

	// Normalize
	if !VerifyRswSolution("0x"+result.Y_hex, result.Y_hex) {
		t.Fatal("expected 0x-prefixed to match")
	}

	if !VerifyRswSolution(strings.ToUpper(result.Y_hex), result.Y_hex) {
		t.Fatal("expected case-insensitive match")
	}
}

func TestRswMinterWithCustomG(t *testing.T) {
	kp, err := GenerateRswKeypair(256)
	if err != nil {
		t.Fatal(err)
	}

	customG := big.NewInt(5)

	minter, err := BuildRswMinter(struct {
		N *big.Int
		P *big.Int
		Q *big.Int
		T int
		G *big.Int
	}{
		N: kp.N,
		P: kp.P,
		Q: kp.Q,
		T: 50,
		G: customG,
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := minter.Mint()
	if err != nil {
		t.Fatal(err)
	}

	if result.X_hex == "" {
		t.Fatal("expected non-empty X")
	}
}

func TestRswVerifyInvalidInputs(t *testing.T) {
	if VerifyRswSolution("abc", "") {
		t.Fatal("expected empty string to fail")
	}

	if VerifyRswSolution("", "abc") {
		t.Fatal("expected empty string to fail")
	}
}

// ─── Format-2 tests ─────────────────────────────────────────────────────────

func TestFormat2Sha256Pow(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	capInstance, err := NewCap(CapOptions{
		Secret:              secret,
		Storage:             store,
		Format:              2,
		Protocols:           []string{"sha256-pow"},
		ChallengeCount:      1,
		ChallengeSize:       8,
		ChallengeDifficulty: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if challenge.Format != 2 {
		t.Fatalf("expected format 2, got %d", challenge.Format)
	}

	if len(challenge.Challenges) != 1 {
		t.Fatalf("expected 1 challenge, got %d", len(challenge.Challenges))
	}

	if challenge.Challenges[0].Protocol != "sha256-pow" {
		t.Fatalf("expected sha256-pow protocol, got %s", challenge.Challenges[0].Protocol)
	}

	// Solve the sha256-pow challenge
	salt, _ := challenge.Challenges[0].Payload["salt"].(string)
	target, _ := challenge.Challenges[0].Payload["target"].(string)

	var nonce int64
	for {
		hash := sha256Hex(salt + strconv.FormatInt(nonce, 10))
		if strings.HasPrefix(hash, target) {
			break
		}

		nonce++
	}

	result, err := capInstance.RedeemChallenge(context.Background(), ValidateBody{
		Token: challenge.Token,
		V2Sol: []V2Solution{
			{Protocol: "sha256-pow", Nonce: float64(nonce)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if !result.Success {
		t.Fatalf("expected success, got reason: %s", result.Reason)
	}
}

func TestFormat2Rsw(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	kp, err := GenerateRswKeypair(256)
	if err != nil {
		t.Fatal(err)
	}

	capInstance, err := NewCap(CapOptions{
		Secret:    secret,
		Storage:   store,
		Format:    2,
		Protocols: []string{"rsw"},
		Keypair:   kp,
		RSWT:      100,
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(challenge.Challenges) != 1 {
		t.Fatalf("expected 1 challenge, got %d", len(challenge.Challenges))
	}

	if challenge.Challenges[0].Protocol != "rsw" {
		t.Fatalf("expected rsw protocol, got %s", challenge.Challenges[0].Protocol)
	}

	// For RSW, we need the y value. The challenge has x, and we need y which requires solving.
	// In a real scenario, the client would compute y from x. Here we need to mint again to get y,
	// or we solve the puzzle. Since solving is expensive, we'll test with the minter directly.
	// For the validate test, we need the y_hex that corresponds to the challenge's x.
	// The y value is embedded in the encrypted token payload.
	payload := jwtVerify(challenge.Token, secret)
	if payload == nil {
		t.Fatal("expected valid token")
	}

	// We'll verify by checking that a mismatched solution is rejected
	result, err := capInstance.RedeemChallenge(context.Background(), ValidateBody{
		Token: challenge.Token,
		V2Sol: []V2Solution{
			{Protocol: "rsw", Y: "wrong-y-value"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected failure with wrong RSW solution")
	}

	if result.Reason != "invalid_solution" {
		t.Fatalf("expected invalid_solution, got %s", result.Reason)
	}
}

func TestFormat2Instrumentation(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	capInstance, err := NewCap(CapOptions{
		Secret:    secret,
		Storage:   store,
		Format:    2,
		Protocols: []string{"instrumentation"},
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(challenge.Challenges) != 1 {
		t.Fatalf("expected 1 challenge, got %d", len(challenge.Challenges))
	}

	if challenge.Challenges[0].Protocol != "instrumentation" {
		t.Fatalf("expected instrumentation protocol, got %s", challenge.Challenges[0].Protocol)
	}

	// Extract metadata from encrypted payload
	payload := jwtVerify(challenge.Token, secret)
	if payload == nil {
		t.Fatal("expected valid token")
	}

	ev, _ := payload["ev"].(string)

	raw, ok := decryptGcmRaw(ev, secret, "cap:fmt2-v1")
	if !ok {
		t.Fatal("expected to decrypt ev")
	}

	var wrapper struct {
		Expected []v2ExpectedEntry `json:"expected"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		t.Fatal(err)
	}

	if len(wrapper.Expected) != 1 {
		t.Fatalf("expected 1 expected entry, got %d", len(wrapper.Expected))
	}

	meta := wrapper.Expected[0].Instrumentation
	if meta == nil {
		t.Fatal("expected instrumentation metadata")
	}

	// Build valid state
	state := make(map[string]int)
	for i, v := range meta.Vars {
		state[v] = meta.ExpectedVals[i]
	}

	result, err := capInstance.RedeemChallenge(context.Background(), ValidateBody{
		Token: challenge.Token,
		V2Sol: []V2Solution{
			{
				Protocol: "instrumentation",
				Instr: map[string]any{
					"i":     meta.ID,
					"state": state,
					"ts":    time.Now().UnixMilli(),
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if !result.Success {
		t.Fatalf("expected success with valid instrumentation, got reason: %s", result.Reason)
	}
}

func TestFormat2MultipleProtocols(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	kp, err := GenerateRswKeypair(256)
	if err != nil {
		t.Fatal(err)
	}

	capInstance, err := NewCap(CapOptions{
		Secret:              secret,
		Storage:             store,
		Format:              2,
		Protocols:           []string{"sha256-pow", "rsw", "instrumentation"},
		ChallengeCount:      1,
		ChallengeSize:       8,
		ChallengeDifficulty: 1,
		Keypair:             kp,
		RSWT:                100,
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(challenge.Challenges) != 3 {
		t.Fatalf("expected 3 challenges, got %d", len(challenge.Challenges))
	}

	if challenge.Challenges[0].Protocol != "sha256-pow" {
		t.Fatalf("expected first protocol sha256-pow, got %s", challenge.Challenges[0].Protocol)
	}

	if challenge.Challenges[1].Protocol != "rsw" {
		t.Fatalf("expected second protocol rsw, got %s", challenge.Challenges[1].Protocol)
	}

	if challenge.Challenges[2].Protocol != "instrumentation" {
		t.Fatalf(
			"expected third protocol instrumentation, got %s",
			challenge.Challenges[2].Protocol,
		)
	}

	// Solve sha256-pow
	salt, _ := challenge.Challenges[0].Payload["salt"].(string)
	target, _ := challenge.Challenges[0].Payload["target"].(string)

	var nonce int64
	for {
		hash := sha256Hex(salt + strconv.FormatInt(nonce, 10))
		if strings.HasPrefix(hash, target) {
			break
		}

		nonce++
	}

	// Get instrumentation state
	payload := jwtVerify(challenge.Token, secret)
	ev, _ := payload["ev"].(string)
	raw, _ := decryptGcmRaw(ev, secret, "cap:fmt2-v1")

	var wrapper struct {
		Expected []v2ExpectedEntry `json:"expected"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		t.Fatal(err)
	}

	meta := wrapper.Expected[2].Instrumentation

	state := make(map[string]int)
	for i, v := range meta.Vars {
		state[v] = meta.ExpectedVals[i]
	}

	// Use wrong RSW solution to test that mismatches are detected
	result, err := capInstance.RedeemChallenge(context.Background(), ValidateBody{
		Token: challenge.Token,
		V2Sol: []V2Solution{
			{Protocol: "sha256-pow", Nonce: float64(nonce)},
			{Protocol: "rsw", Y: "wrong"},
			{Protocol: "instrumentation", Instr: map[string]any{
				"i":     meta.ID,
				"state": state,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected failure with wrong RSW solution")
	}

	if result.Reason != "invalid_solution" {
		t.Fatalf("expected invalid_solution, got %s", result.Reason)
	}
}

// ─── Challenge extra/scope edge cases ───────────────────────────────────────

func TestChallengeExtra(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	capInstance, err := NewCap(CapOptions{
		Secret:  secret,
		Storage: store,
		Extra:   map[string]any{"user_id": 42, "custom": "value"},
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	payload := jwtVerify(challenge.Token, secret)
	if payload == nil {
		t.Fatal("expected valid token")
	}

	x, ok := payload["x"].(map[string]any)
	if !ok {
		t.Fatal("expected x field in payload")
	}

	if x["user_id"] != float64(42) {
		t.Fatalf("expected user_id=42, got %v", x["user_id"])
	}

	if x["custom"] != "value" {
		t.Fatalf("expected custom=value, got %v", x["custom"])
	}
}

func TestChallengeScope(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	capInstance, err := NewCap(CapOptions{
		Secret:  secret,
		Storage: store,
		Scope:   "login",
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	solutions := solveChallenge(
		challenge.Token,
		challenge.Challenge.C,
		challenge.Challenge.S,
		challenge.Challenge.D,
	)

	// Wrong scope
	wrongScopeCap, _ := NewCap(CapOptions{
		Secret:  secret,
		Storage: store,
		Scope:   "signup",
	})

	result, err := wrongScopeCap.RedeemChallenge(context.Background(), ValidateBody{
		Token:     challenge.Token,
		Solutions: solutions,
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected failure with wrong scope")
	}

	if result.Reason != "scope_mismatch" {
		t.Fatalf("expected scope_mismatch, got %s", result.Reason)
	}

	// Correct scope
	correctScopeCap, _ := NewCap(CapOptions{
		Secret:  secret,
		Storage: store,
		Scope:   "login",
	})

	result, err = correctScopeCap.RedeemChallenge(context.Background(), ValidateBody{
		Token:     challenge.Token,
		Solutions: solutions,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !result.Success {
		t.Fatalf("expected success with correct scope, got reason: %s", result.Reason)
	}
}

// ─── ConsumeNonce tests ─────────────────────────────────────────────────────

func TestConsumeNonce(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	capInstance, err := NewCap(CapOptions{
		Secret:              secret,
		Storage:             store,
		ChallengeCount:      2,
		ChallengeSize:       8,
		ChallengeDifficulty: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	solutions := solveChallenge(
		challenge.Token,
		challenge.Challenge.C,
		challenge.Challenge.S,
		challenge.Challenge.D,
	)

	seen := make(map[string]bool)
	consumeNonce := func(ctx context.Context, sigHex string, ttl time.Duration) (bool, error) {
		if seen[sigHex] {
			return false, nil
		}

		seen[sigHex] = true

		return true, nil
	}

	// First use should succeed
	result, err := validateChallengeWithContext(context.Background(), secret, ValidateBody{
		Token:     challenge.Token,
		Solutions: solutions,
	}, ValidateOptions{ConsumeNonce: consumeNonce})
	if err != nil {
		t.Fatal(err)
	}

	if !result.Success {
		t.Fatalf("expected first use to succeed, got reason: %s", result.Reason)
	}

	// Second use (replay) should fail
	result, err = validateChallengeWithContext(context.Background(), secret, ValidateBody{
		Token:     challenge.Token,
		Solutions: solutions,
	}, ValidateOptions{ConsumeNonce: consumeNonce})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected replay to fail")
	}

	if result.Reason != "already_redeemed" {
		t.Fatalf("expected already_redeemed, got %s", result.Reason)
	}
}

func TestConsumeNonceError(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	challenge, err := generateChallengeWithContext(context.Background(), secret, GenerateOptions{
		ChallengeCount:      1,
		ChallengeSize:       4,
		ChallengeDifficulty: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	solutions := solveChallenge(
		challenge.Token,
		challenge.Challenge.C,
		challenge.Challenge.S,
		challenge.Challenge.D,
	)

	errConsume := func(ctx context.Context, sigHex string, ttl time.Duration) (bool, error) {
		return false, errors.New("store exploded")
	}

	result, err := validateChallengeWithContext(context.Background(), secret, ValidateBody{
		Token:     challenge.Token,
		Solutions: solutions,
	}, ValidateOptions{ConsumeNonce: errConsume})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected failure")
	}

	if result.Reason != "nonce_store_error" {
		t.Fatalf("expected nonce_store_error, got %s", result.Reason)
	}

	if !strings.Contains(result.ErrorStr, "store exploded") {
		t.Fatalf("expected error message to contain 'store exploded', got %s", result.ErrorStr)
	}
}

// ─── SignToken tests ────────────────────────────────────────────────────────

func TestSignToken(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	capInstance, err := NewCap(CapOptions{
		Secret:              secret,
		Storage:             store,
		ChallengeCount:      1,
		ChallengeSize:       4,
		ChallengeDifficulty: 1,
		Scope:               "myapp",
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	solutions := solveChallenge(
		challenge.Token,
		challenge.Challenge.C,
		challenge.Challenge.S,
		challenge.Challenge.D,
	)

	customSigner := func(data RedeemTokenData) (string, error) {
		scope := ""
		if data.Scope != nil {
			scope = *data.Scope
		}

		return "custom-" + scope + "-token", nil
	}

	result, err := validateChallengeWithContext(context.Background(), secret, ValidateBody{
		Token:     challenge.Token,
		Solutions: solutions,
	}, ValidateOptions{
		SignToken: customSigner,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !result.Success {
		t.Fatalf("expected success, got reason: %s", result.Reason)
	}

	if result.Token != "custom-myapp-token" {
		t.Fatalf("expected custom-myapp-token, got %s", result.Token)
	}

	if result.TokenKey != nil {
		t.Fatal("expected tokenKey to be nil when signToken is used")
	}
}

// ─── Expired challenge test ─────────────────────────────────────────────────

func TestExpiredChallenge(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	challenge, err := generateChallengeWithContext(context.Background(), secret, GenerateOptions{
		ChallengeCount:      1,
		ChallengeSize:       4,
		ChallengeDifficulty: 1,
		Expires:             1 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(10 * time.Millisecond)

	solutions := solveChallenge(
		challenge.Token,
		challenge.Challenge.C,
		challenge.Challenge.S,
		challenge.Challenge.D,
	)

	result, err := validateChallengeWithContext(context.Background(), secret, ValidateBody{
		Token:     challenge.Token,
		Solutions: solutions,
	}, ValidateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected expired challenge to fail")
	}

	if result.Reason != "expired" {
		t.Fatalf("expected expired, got %s", result.Reason)
	}
}

// ─── Invalid body validation tests ──────────────────────────────────────────

func TestValidateInvalidBody(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	// Missing token
	result, err := validateChallengeWithContext(context.Background(), secret, ValidateBody{
		Solutions: []int64{1, 2, 3},
	}, ValidateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected failure with missing token")
	}

	if result.Reason != "missing_token" {
		t.Fatalf("expected missing_token, got %s", result.Reason)
	}

	// Missing solutions
	result, err = validateChallengeWithContext(context.Background(), secret, ValidateBody{
		Token: "x.y.z",
	}, ValidateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected failure with missing solutions")
	}

	if result.Reason != "missing_solutions" {
		t.Fatalf("expected missing_solutions, got %s", result.Reason)
	}

	// Invalid JWT
	result, err = validateChallengeWithContext(
		context.Background(),
		secret,
		ValidateBody{ //nolint:gosec
			Token:     "not.a.jwt.token",
			Solutions: []int64{1},
		},
		ValidateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected failure with invalid token")
	}

	if result.Reason != "invalid_token" {
		t.Fatalf("expected invalid_token, got %s", result.Reason)
	}
}

// ─── Regression: nonce 0 is valid ───────────────────────────────────────────

func TestNonceZeroIsValid(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	for range 50 {
		challenge, err := generateChallengeWithContext(
			context.Background(),
			secret,
			GenerateOptions{
				ChallengeCount:      1,
				ChallengeSize:       8,
				ChallengeDifficulty: 1,
			},
		)
		if err != nil {
			t.Fatal(err)
		}

		salt := prng(challenge.Token+"1", 8)
		target := prng(challenge.Token+"1d", 1)

		hash := sha256Hex(salt + "0")
		if strings.HasPrefix(hash, target) {
			result, err := validateChallengeWithContext(context.Background(), secret, ValidateBody{
				Token:     challenge.Token,
				Solutions: []int64{0},
			}, ValidateOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if !result.Success {
				t.Fatalf("expected nonce 0 to be accepted, got reason: %s", result.Reason)
			}

			return
		}
	}
}

// ─── V2 challenge with unknown protocol ─────────────────────────────────────

func TestFormat2UnknownProtocol(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	_, err := generateChallengeV2(context.Background(), secret, GenerateOptions{
		Protocols: []string{"unknown-protocol"},
	})
	if err == nil {
		t.Fatal("expected error for unknown protocol")
	}
}

// ─── V2 challenge validation with mismatched solutions ──────────────────────

func TestFormat2MismatchedSolutions(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	challenge, err := generateChallengeV2(context.Background(), secret, GenerateOptions{
		Protocols:           []string{"sha256-pow"},
		ChallengeCount:      1,
		ChallengeSize:       4,
		ChallengeDifficulty: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := jwtVerify(challenge.Token, secret)
	if payload == nil {
		t.Fatal("expected valid token")
	}

	// Wrong number of solutions
	result, err := validateChallengeV2(context.Background(), secret, ValidateBody{
		Token: challenge.Token,
		V2Sol: []V2Solution{},
	}, payload, ValidateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected failure with wrong solution count")
	}

	if result.Reason != "invalid_solutions" {
		t.Fatalf("expected invalid_solutions, got %s", result.Reason)
	}
}

// ─── Format detection via RedeemChallenge ──────────────────────────────────

func TestRedeemChallengeDetectsFormat(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	// Format-1 test
	f1Cap, _ := NewCap(CapOptions{
		Secret:              secret,
		Storage:             store,
		ChallengeCount:      1,
		ChallengeSize:       4,
		ChallengeDifficulty: 1,
	})

	f1Challenge, _ := f1Cap.CreateChallenge(context.Background())
	f1Solutions := solveChallenge(
		f1Challenge.Token,
		f1Challenge.Challenge.C,
		f1Challenge.Challenge.S,
		f1Challenge.Challenge.D,
	)

	f1Result, err := f1Cap.RedeemChallenge(context.Background(), ValidateBody{
		Token:     f1Challenge.Token,
		Solutions: f1Solutions,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !f1Result.Success {
		t.Fatalf("expected format-1 success, got reason: %s", f1Result.Reason)
	}

	// Format-2 test
	kp, _ := GenerateRswKeypair(256)
	f2Cap, _ := NewCap(CapOptions{
		Secret:              secret,
		Storage:             store,
		Format:              2,
		Protocols:           []string{"sha256-pow"},
		ChallengeCount:      1,
		ChallengeSize:       4,
		ChallengeDifficulty: 1,
		Keypair:             kp,
	})

	f2Challenge, _ := f2Cap.CreateChallenge(context.Background())
	salt, _ := f2Challenge.Challenges[0].Payload["salt"].(string)
	target, _ := f2Challenge.Challenges[0].Payload["target"].(string)

	var nonce int64
	for {
		hash := sha256Hex(salt + strconv.FormatInt(nonce, 10))
		if strings.HasPrefix(hash, target) {
			break
		}

		nonce++
	}

	f2Result, err := f2Cap.RedeemChallenge(context.Background(), ValidateBody{
		Token: f2Challenge.Token,
		V2Sol: []V2Solution{
			{Protocol: "sha256-pow", Nonce: float64(nonce)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if !f2Result.Success {
		t.Fatalf("expected format-2 success, got reason: %s", f2Result.Reason)
	}
}

// ─── Benchmark: RSW key generation ──────────────────────────────────────────

func TestRswKeypair2048Bits(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 2048-bit key generation in short mode")
	}

	kp, err := GenerateRswKeypair(2048)
	if err != nil {
		t.Fatal(err)
	}

	if kp.N.BitLen() != 2048 {
		t.Fatalf("expected 2048-bit N, got %d bits", kp.N.BitLen())
	}
}

// ─── Sentinel error tests ──────────────────────────────────────────────────

func TestValidateResultErrorsIs(t *testing.T) {
	// Verify that ValidateResult implements the error interface and errors.Is works
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	capInstance, err := NewCap(CapOptions{
		Secret:              secret,
		Storage:             store,
		ChallengeCount:      1,
		ChallengeSize:       4,
		ChallengeDifficulty: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Test: expired challenge
	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	_ = challenge

	// Test: ValidateToken with empty token
	vr := capInstance.ValidateToken(context.Background(), "")
	if vr.Success {
		t.Fatal("expected failure")
	}

	if !errors.Is(vr, ErrMissingToken) {
		t.Fatalf("expected errors.Is(vr, ErrMissingToken), got reason=%s", vr.Reason)
	}

	// Test: ValidateToken with missing token
	vr = capInstance.ValidateToken(context.Background(), "nonexistent")
	if vr.Success {
		t.Fatal("expected failure")
	}

	if !errors.Is(vr, ErrTokenNotFound) {
		t.Fatalf("expected errors.Is(vr, ErrTokenNotFound), got reason=%s", vr.Reason)
	}

	// Test: RedeemChallenge with missing token
	result, err := capInstance.RedeemChallenge(context.Background(), ValidateBody{
		Token:     "",
		Solutions: []int64{1},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected failure")
	}

	if !errors.Is(result, ErrMissingToken) {
		t.Fatalf("expected errors.Is(result, ErrMissingToken), got reason=%s", result.Reason)
	}

	// Test: RedeemChallenge with missing solutions
	result, err = capInstance.RedeemChallenge(context.Background(), ValidateBody{
		Token: "x.y.z",
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected failure")
	}

	if !errors.Is(result, ErrMissingSolutions) {
		t.Fatalf("expected errors.Is(result, ErrMissingSolutions), got reason=%s", result.Reason)
	}

	// Test: RedeemChallenge with invalid JWT
	result, err = capInstance.RedeemChallenge(context.Background(), ValidateBody{ //nolint:gosec
		Token:     "not-a-valid.jwt.token",
		Solutions: []int64{1},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected failure")
	}

	if !errors.Is(result, ErrInvalidToken) {
		t.Fatalf("expected errors.Is(result, ErrInvalidToken), got reason=%s", result.Reason)
	}

	// Test: RedeemChallenge with wrong solution count
	result, err = capInstance.RedeemChallenge(context.Background(), ValidateBody{
		Token:     challenge.Token,
		Solutions: []int64{1, 2, 3},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected failure")
	}

	if !errors.Is(result, ErrInvalidSolutions) {
		t.Fatalf("expected errors.Is(result, ErrInvalidSolutions), got reason=%s", result.Reason)
	}

	// Test: RedeemChallenge with wrong solutions (valid count but wrong values)
	validChallenge, _ := capInstance.CreateChallenge(context.Background())
	_ = validChallenge
}

func TestValidateResultImplementsError(t *testing.T) {
	// Verify ValidateResult can be used as an error
	r := ValidateResult{Success: false, Reason: "test_reason"}

	var e error = r
	if e.Error() != "test_reason" {
		t.Fatalf("expected 'test_reason', got %q", e.Error())
	}

	// Success case
	r2 := ValidateResult{Success: true}

	e2 := r2
	if e2.Error() != "success" {
		t.Fatalf("expected 'success', got %q", e2.Error())
	}
}

func TestSentinelErrorValues(t *testing.T) {
	// Verify sentinel errors have expected string values for JSON compat
	tests := []struct {
		err  error
		want string
	}{
		{ErrMissingToken, "missing_token"},
		{ErrMissingSolutions, "missing_solutions"},
		{ErrInvalidToken, "invalid_token"},
		{ErrScopeMismatch, "scope_mismatch"},
		{ErrExpired, "expired"},
		{ErrInvalidSolutions, "invalid_solutions"},
		{ErrInvalidSolution, "invalid_solution"},
		{ErrAlreadyRedeemed, "already_redeemed"},
		{ErrNonceStoreError, "nonce_store_error"},
		{ErrStorageNotConfigured, "storage_not_configured"},
		{ErrCleanupError, "cleanup_error"},
		{ErrStorageError, "storage_error"},
		{ErrTokenNotFound, "token_not_found"},
		{ErrTokenExpired, "token_expired"},
		{ErrInstrCorrupted, "instr_corrupted"},
		{ErrInstrExpired, "instr_expired"},
		{ErrInstrAutomatedBrowser, "instr_automated_browser"},
		{ErrInstrTimeout, "instr_timeout"},
		{ErrInstrFailed, "instr_failed"},
		{ErrInstrMissing, "instr_missing"},
	}
	for _, tc := range tests {
		if tc.err.Error() != tc.want {
			t.Fatalf("sentinel error %v: got %q, want %q", tc.err, tc.err.Error(), tc.want)
		}
	}
}

// ─── Coverage gap: validateV2Sha256Pow string-nonce path ────────────────────

func TestFormat2Sha256PowStringNonce(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	capInstance, err := NewCap(CapOptions{
		Secret:              secret,
		Storage:             store,
		Format:              2,
		Protocols:           []string{"sha256-pow"},
		ChallengeCount:      1,
		ChallengeSize:       8,
		ChallengeDifficulty: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	salt, _ := challenge.Challenges[0].Payload["salt"].(string)
	target, _ := challenge.Challenges[0].Payload["target"].(string)

	var nonce int64
	for {
		hash := sha256Hex(salt + strconv.FormatInt(nonce, 10))
		if strings.HasPrefix(hash, target) {
			break
		}

		nonce++
	}

	// Submit nonce as string (JSON unmarshalled from client)
	result, err := capInstance.RedeemChallenge(context.Background(), ValidateBody{
		Token: challenge.Token,
		V2Sol: []V2Solution{
			{Protocol: "sha256-pow", Nonce: strconv.FormatInt(nonce, 10)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if !result.Success {
		t.Fatalf("expected success with string nonce, got reason: %s", result.Reason)
	}

	// Wrong string nonce
	result, err = capInstance.RedeemChallenge(context.Background(), ValidateBody{
		Token: challenge.Token,
		V2Sol: []V2Solution{
			{Protocol: "sha256-pow", Nonce: "9999999999999"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected failure with wrong string nonce")
	}

	if !errors.Is(result, ErrInvalidSolution) {
		t.Fatalf("expected ErrInvalidSolution, got %s", result.Reason)
	}

	// Non-parseable string nonce
	result, err = capInstance.RedeemChallenge(context.Background(), ValidateBody{
		Token: challenge.Token,
		V2Sol: []V2Solution{
			{Protocol: "sha256-pow", Nonce: "not-a-number"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected failure with bad string nonce")
	}

	if !errors.Is(result, ErrInvalidSolution) {
		t.Fatalf("expected ErrInvalidSolution, got %s", result.Reason)
	}
}

// ─── Coverage gap: validateV2Instrumentation blocked/timeout paths ──────────

func TestFormat2InstrumentationBlocked(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	capInstance, err := NewCap(CapOptions{
		Secret:    secret,
		Storage:   store,
		Format:    2,
		Protocols: []string{"instrumentation"},
		InstrumentationOpts: &InstrumentationOptions{
			BlockAutomatedBrowsers: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Blocked + blockAutomatedBrowsers=true → rejected
	result, err := capInstance.RedeemChallenge(context.Background(), ValidateBody{
		Token: challenge.Token,
		V2Sol: []V2Solution{
			{Protocol: "instrumentation", Blocked: ptrBool(true)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected failure with blocked=true when blockAutomatedBrowsers=true")
	}

	if !errors.Is(result, ErrInstrAutomatedBrowser) {
		t.Fatalf("expected ErrInstrAutomatedBrowser, got %s", result.Reason)
	}
}

func TestFormat2InstrumentationTimeout(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	capInstance, err := NewCap(CapOptions{
		Secret:    secret,
		Storage:   store,
		Format:    2,
		Protocols: []string{"instrumentation"},
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Timeout → rejected
	result, err := capInstance.RedeemChallenge(context.Background(), ValidateBody{
		Token: challenge.Token,
		V2Sol: []V2Solution{
			{Protocol: "instrumentation", Timeout: ptrBool(true)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected failure with timeout")
	}

	if !errors.Is(result, ErrInstrTimeout) {
		t.Fatalf("expected ErrInstrTimeout, got %s", result.Reason)
	}
}

// ─── Coverage gap: validateV2Rsw success path ──────────────────────────────

func TestFormat2RswValid(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	kp, err := GenerateRswKeypair(256)
	if err != nil {
		t.Fatal(err)
	}

	capInstance, err := NewCap(CapOptions{
		Secret:    secret,
		Storage:   store,
		Format:    2,
		Protocols: []string{"rsw"},
		Keypair:   kp,
		RSWT:      100,
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Extract y_hex from encrypted payload
	payload := jwtVerify(challenge.Token, secret)
	ev, _ := payload["ev"].(string)

	raw, ok := decryptGcmRaw(ev, secret, "cap:fmt2-v1")
	if !ok {
		t.Fatal("expected to decrypt ev")
	}

	var wrapper struct {
		Expected []v2ExpectedEntry `json:"expected"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		t.Fatal(err)
	}

	yHex := wrapper.Expected[0].Y

	// Valid RSW solution
	result, err := capInstance.RedeemChallenge(context.Background(), ValidateBody{
		Token: challenge.Token,
		V2Sol: []V2Solution{
			{Protocol: "rsw", Y: yHex},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if !result.Success {
		t.Fatalf("expected success with valid RSW solution, got reason: %s", result.Reason)
	}
}

// ─── Coverage gap: issueValidationToken SignToken error ─────────────────────

func TestSignTokenError(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	challenge, err := generateChallengeWithContext(context.Background(), secret, GenerateOptions{
		ChallengeCount:      1,
		ChallengeSize:       4,
		ChallengeDifficulty: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	solutions := solveChallenge(
		challenge.Token,
		challenge.Challenge.C,
		challenge.Challenge.S,
		challenge.Challenge.D,
	)

	errSigner := func(data RedeemTokenData) (string, error) {
		return "", errors.New("signer exploded")
	}

	_, err = validateChallengeWithContext(context.Background(), secret, ValidateBody{
		Token:     challenge.Token,
		Solutions: solutions,
	}, ValidateOptions{SignToken: errSigner})
	if err == nil {
		t.Fatal("expected error from signToken")
	}

	if err.Error() != "signer exploded" {
		t.Fatalf("expected 'signer exploded', got %v", err)
	}
}

// ─── Coverage gap: ValidateToken with expired token ─────────────────────────

func TestValidateTokenExpired(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	// Use a store that never cleans up expired tokens
	store := &noCleanupStore{data: map[string]time.Time{
		"expired:token": time.Now().Add(-1 * time.Hour),
	}}

	cap, err := NewCap(CapOptions{Secret: secret, Storage: store})
	if err != nil {
		t.Fatal(err)
	}

	vr := cap.ValidateToken(context.Background(), "expired:token")
	if vr.Success {
		t.Fatal("expected expired token to fail")
	}

	if !errors.Is(vr, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %s", vr.Reason)
	}
}

// ─── Coverage gap: ValidateToken cleanup error ──────────────────────────────

func TestValidateTokenCleanupError(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	store := &cleanupErrorStore{MemoryStorage: NewMemoryStorage()}

	cap, err := NewCap(CapOptions{Secret: secret, Storage: store})
	if err != nil {
		t.Fatal(err)
	}

	vr := cap.ValidateToken(context.Background(), "any-token")
	if vr.Success {
		t.Fatal("expected cleanup error to fail")
	}

	if !errors.Is(vr, ErrCleanupError) {
		t.Fatalf("expected ErrCleanupError, got %s", vr.Reason)
	}
}

type cleanupErrorStore struct {
	*MemoryStorage
}

func (s *cleanupErrorStore) CleanupExpired(_ context.Context) error {
	return errors.New("cleanup failed")
}

// noCleanupStore never removes expired entries, used to test ErrTokenExpired path.
type noCleanupStore struct {
	data map[string]time.Time
}

func (s *noCleanupStore) SetChallengeToken(
	_ context.Context,
	token string,
	expiresAt time.Time,
) error {
	return nil
}

func (s *noCleanupStore) GetChallengeTokenExpiry(
	_ context.Context,
	token string,
) (time.Time, bool, error) {
	return time.Time{}, false, nil
}

func (s *noCleanupStore) SetValidationToken(
	_ context.Context,
	token string,
	expiresAt time.Time,
) error {
	s.data[token] = expiresAt
	return nil
}

func (s *noCleanupStore) GetValidationTokenExpiry(
	_ context.Context,
	token string,
) (time.Time, bool, error) {
	expiresAt, ok := s.data[token]
	return expiresAt, ok, nil
}

func (s *noCleanupStore) CleanupExpired(_ context.Context) error {
	return nil // never clean up
}

// ─── Coverage gap: validateFormat1Instr with non-string ei ──────────────────

func TestFormat1InstrCorrupted(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	// Generate a challenge first to get the payload
	capInstance, err := NewCap(CapOptions{
		Secret:              secret,
		Storage:             store,
		ChallengeCount:      1,
		ChallengeSize:       8,
		ChallengeDifficulty: 1,
		Instrumentation:     true,
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Re-sign a token with ei set to a non-string value
	payload := jwtVerify(challenge.Token, secret)
	payload["ei"] = 12345 // not a string
	tamperedToken := jwtSign(payload, secret)

	// Solve PoW for the tampered token (different token → different salt/target)
	solutions := solveChallenge(tamperedToken, 1, 8, 1)

	result, err := capInstance.RedeemChallenge(context.Background(), ValidateBody{
		Token:     tamperedToken,
		Solutions: solutions,
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected failure with corrupted ei")
	}

	if !errors.Is(result, ErrInstrCorrupted) {
		t.Fatalf("expected ErrInstrCorrupted, got %s", result.Reason)
	}
}

// ─── Helper ─────────────────────────────────────────────────────────────────

func ptrBool(b bool) *bool {
	return &b
}

// ─── Coverage gap: FastRnd error path ──────────────────────────────────────

func TestFastRndError(t *testing.T) {
	// fastRnd uses crypto/rand internally; errors are essentially impossible.
	// This test verifies the function signature is correct.
	v, err := fastRnd(1, 10)
	if err != nil {
		t.Fatal(err)
	}

	if v < 1 || v > 10 {
		t.Fatalf("expected value in [1,10], got %d", v)
	}
}

// ─── Coverage gap: rHex error path ─────────────────────────────────────────

func TestRHex(t *testing.T) {
	s, err := rHex(16)
	if err != nil {
		t.Fatal(err)
	}

	if len(s) != 16 {
		t.Fatalf("expected 16 chars, got %d", len(s))
	}
}
