package gocap

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func probeFrom(t *testing.T, v map[string]any) ProbeVector {
	t.Helper()

	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	var p ProbeVector
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}

	return p
}

func fracWidths(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = 1200.88 + float64(i)*3.17
	}

	return out
}

func intWidths(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = float64(1200 + i*3)
	}

	return out
}

func chromeHumanProbe(t *testing.T) ProbeVector {
	t.Helper()

	return probeFrom(t, map[string]any{
		"ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
			"(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
		"productSub":    "20030107",
		"webdriver":     false,
		"oscpu":         "__undefined",
		"deviceMemory":  8.0,
		"uaDataPresent": true,
		"uaData": map[string]any{
			"mobile": false,
			"brands": []any{"Google Chrome/151", "Chromium/151", "Not.A/Brand/99"},
		},
		"plugins":          map[string]any{"length": 5.0},
		"pdfViewerEnabled": true,
		"engine":           map[string]any{"hasMozInnerScreenX": false, "hasChrome": true},
		"screen":           map[string]any{"width": 1920.0, "height": 1080.0},
		"innerWH":          []any{945.0, 868.0},
		"outerWH":          []any{945.0, 1060.0},
		"isExtended":       false,
		"fontWidths":       fracWidths(17),
		"tamper": map[string]any{
			"getParameterWebGL": true,
			"toDataURL":         true,
			"getImageData":      true,
			"permissionsQuery":  true,
			"fnToString":        true,
		},
	})
}

func firefoxHumanProbe(t *testing.T) ProbeVector {
	t.Helper()

	return probeFrom(t, map[string]any{
		"ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:154.0) " +
			"Gecko/20100101 Firefox/154.0",
		"productSub":       "20100101",
		"webdriver":        false,
		"oscpu":            "Intel Mac OS X 10.15",
		"uaDataPresent":    false,
		"uaData":           nil,
		"plugins":          map[string]any{"length": 5.0},
		"pdfViewerEnabled": true,
		"engine":           map[string]any{"hasMozInnerScreenX": true, "hasChrome": false},
		"screen":           map[string]any{"width": 1920.0, "height": 1080.0},
		"innerWH":          []any{1200.0, 900.0},
		"outerWH":          []any{1200.0, 985.0},
		"isExtended":       false,
		"fontWidths":       fracWidths(17),
		"tamper": map[string]any{
			"getParameterWebGL": true,
			"toDataURL":         true,
			"getImageData":      true,
			"permissionsQuery":  true,
			"fnToString":        true,
		},
	})
}

func TestDetectAutomationHumans(t *testing.T) {
	for name, probe := range map[string]ProbeVector{
		"chrome":  chromeHumanProbe(t),
		"firefox": firefoxHumanProbe(t),
	} {
		count := len(ProbeFontStacks)

		r := DetectAutomation(probe, &DetectOptions{FontStackCount: &count})
		if !r.Pass || len(r.BlockedBy) != 0 {
			t.Fatalf("%s: expected pass, got pass=%v blockedBy=%v", name, r.Pass, r.BlockedBy)
		}
	}
}

func TestDetectAutomationBots(t *testing.T) {
	count := len(ProbeFontStacks)

	tests := []struct {
		name    string
		mutate  func(ProbeVector)
		blocked []string
		flags   []string
	}{
		{
			name:    "quantized geometry",
			mutate:  func(p ProbeVector) { p["fontWidths"] = intWidths(17) },
			blocked: []string{"geometry_quantized"},
		},
		{
			name:    "webdriver true",
			mutate:  func(p ProbeVector) { p["webdriver"] = true },
			blocked: []string{"webdriver_true"},
		},
		{
			name:    "webdriver stripped",
			mutate:  func(p ProbeVector) { delete(p, "webdriver") },
			blocked: []string{"webdriver_stripped"},
		},
		{
			name: "patchright geometry",
			mutate: func(p ProbeVector) {
				p["screen"] = map[string]any{"width": 1280.0, "height": 720.0}
				p["innerWH"] = []any{1280.0, 720.0}
				p["outerWH"] = []any{1288.0, 805.0}
			},
			blocked: []string{"window_exceeds_screen", "viewport_override"},
		},
		{
			name: "headless brand",
			mutate: func(p ProbeVector) {
				p["uaData"] = map[string]any{
					"mobile": false,
					"brands": []any{"HeadlessChrome/151", "Chromium/151"},
				}
			},
			blocked: []string{"headless_token"},
		},
		{
			name:   "tampered canvas",
			mutate: func(p ProbeVector) { p["tamper"].(map[string]any)["toDataURL"] = false },
			flags:  []string{"native_tamper"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := chromeHumanProbe(t)
			tc.mutate(p)

			r := DetectAutomation(p, &DetectOptions{FontStackCount: &count})

			for _, want := range tc.blocked {
				if !containsString(r.BlockedBy, want) {
					t.Fatalf("expected blockedBy to contain %q, got %v", want, r.BlockedBy)
				}
			}

			for _, want := range tc.flags {
				if !containsString(r.RiskFlags, want) {
					t.Fatalf("expected riskFlags to contain %q, got %v", want, r.RiskFlags)
				}
			}

			if len(tc.blocked) == 0 && !r.Pass {
				t.Fatalf("expected pass, got blockedBy=%v", r.BlockedBy)
			}
		})
	}
}

func TestDetectAutomationProbeCompleteness(t *testing.T) {
	count := len(ProbeFontStacks)

	empty := probeFrom(t, map[string]any{})

	r := DetectAutomation(empty, &DetectOptions{FontStackCount: &count})
	if r.Pass || !containsString(r.BlockedBy, "probe_incomplete") {
		t.Fatalf("expected probe_incomplete, got pass=%v blockedBy=%v", r.Pass, r.BlockedBy)
	}

	fields := []string{"ua", "screen", "outerWH", "fontWidths", "isExtended", "uaDataPresent"}
	for _, field := range fields {
		p := chromeHumanProbe(t)
		delete(p, field)

		r := DetectAutomation(p, &DetectOptions{FontStackCount: &count})
		if !containsString(r.BlockedBy, "probe_incomplete") {
			t.Fatalf("dropping %q: expected probe_incomplete, got %v", field, r.BlockedBy)
		}
	}

	p := chromeHumanProbe(t)
	p["fontWidths"] = []any{1.0, 2.0, 3.0}

	r = DetectAutomation(p, &DetectOptions{FontStackCount: &count})
	if !containsString(r.BlockedBy, "probe_incomplete") {
		t.Fatalf("short fontWidths: expected probe_incomplete, got %v", r.BlockedBy)
	}

	if got := DetectAutomation(nil, nil); got.Pass ||
		!containsString(got.BlockedBy, "probe_missing") {
		t.Fatalf("nil vector: expected probe_missing, got %v", got.BlockedBy)
	}
}

func TestVerifyInstrumentationProbe(t *testing.T) {
	meta := &InstrumentationMeta{
		ID:                     "id",
		Vars:                   []string{"a", "b", "c", "d"},
		ExpectedVals:           []int{1, 2, 3, 4},
		BlockAutomatedBrowsers: true,
	}

	state := map[string]int{"a": 1, "b": 2, "c": 3, "d": 4}

	bot := chromeHumanProbe(t)
	bot["webdriver"] = true

	vr := verifyInstrumentationResult(meta, &InstrumentationResult{I: "id", State: state, P: bot})
	if vr.Valid || vr.Reason != "instr_automated_browser" ||
		!containsString(vr.BlockedBy, "webdriver_true") {
		t.Fatalf("expected instr_automated_browser with webdriver_true, got %+v", vr)
	}

	vr = verifyInstrumentationResult(meta, &InstrumentationResult{I: "id", State: state})
	if vr.Valid || vr.Reason != "instr_probe_missing" {
		t.Fatalf("expected instr_probe_missing, got %+v", vr)
	}

	meta.BlockAutomatedBrowsers = false

	human := chromeHumanProbe(t)
	human["webdriver"] = true
	human["tamper"].(map[string]any)["toDataURL"] = false

	vr = verifyInstrumentationResult(meta, &InstrumentationResult{I: "id", State: state, P: human})
	if !vr.Valid || !containsString(vr.RiskFlags, "native_tamper") {
		t.Fatalf("expected valid with native_tamper risk flag, got %+v", vr)
	}
}

func TestFormat2SolutionsWireShape(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	challenge, err := generateChallengeV2(context.Background(), secret, GenerateOptions{
		Protocols:           []string{"sha256-pow"},
		ChallengeCount:      1,
		ChallengeSize:       8,
		ChallengeDifficulty: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	salt, _ := challenge.Challenges[0].Payload["salt"].(string)
	target, _ := challenge.Challenges[0].Payload["target"].(string)

	nonce := 0
	for !strings.HasPrefix(sha256Hex(salt+strconv.Itoa(nonce)), target) {
		nonce++
	}

	raw := fmt.Sprintf(`{"token":%q,"solutions":[{"nonce":%d}]}`, challenge.Token, nonce)

	var body ValidateBody

	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}

	if len(body.Solutions.Objects) != 1 || body.Solutions.Numbers != nil {
		t.Fatalf("expected format-2 solutions, got %+v", body.Solutions)
	}

	payload := jwtVerify(challenge.Token, secret)

	result, err := validateChallengeV2(
		context.Background(),
		secret,
		body,
		payload,
		ValidateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}

	if !result.Success {
		t.Fatalf("expected success, got %s", result.Reason)
	}

	// Marshal must emit exactly the upstream `solutions` field.
	out, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(out), "v2Sol") || !strings.Contains(string(out), `"solutions"`) {
		t.Fatalf("expected solutions wire field, got %s", out)
	}
}

func TestBlockedMarkerHardening(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	for _, block := range []bool{false, true} {
		c, err := NewCap(CapOptions{
			Secret:              secret,
			Storage:             store,
			ChallengeCount:      1,
			ChallengeSize:       4,
			ChallengeDifficulty: 1,
			Instrumentation:     true,
			InstrumentationOpts: &InstrumentationOptions{BlockAutomatedBrowsers: block},
		})
		if err != nil {
			t.Fatal(err)
		}

		challenge, err := c.CreateChallenge(context.Background())
		if err != nil {
			t.Fatal(err)
		}

		solutions := solveChallenge(challenge.Token, 1, 4, 1)

		result, err := c.RedeemChallenge(context.Background(), ValidateBody{
			Token:     challenge.Token,
			Solutions: SolutionsFromNumbers(solutions),
			Blocked:   true,
		})
		if err != nil {
			t.Fatal(err)
		}

		want := ErrInstrFailed
		if block {
			want = ErrInstrAutomatedBrowser
		}

		if result.Success || !errors.Is(result, want) {
			t.Fatalf(
				"block=%v: expected %s, got success=%v reason=%s",
				block,
				want,
				result.Success,
				result.Reason,
			)
		}
	}

	for _, block := range []bool{false, true} {
		c, err := NewCap(CapOptions{
			Secret:              secret,
			Storage:             store,
			Format:              2,
			Protocols:           []string{"instrumentation"},
			InstrumentationOpts: &InstrumentationOptions{BlockAutomatedBrowsers: block},
		})
		if err != nil {
			t.Fatal(err)
		}

		challenge, err := c.CreateChallenge(context.Background())
		if err != nil {
			t.Fatal(err)
		}

		result, err := c.RedeemChallenge(context.Background(), ValidateBody{
			Token:     challenge.Token,
			Solutions: SolutionsFromObjects([]V2Solution{{Blocked: new(true)}}),
		})
		if err != nil {
			t.Fatal(err)
		}

		want := ErrInstrFailed
		if block {
			want = ErrInstrAutomatedBrowser
		}

		if result.Success || !errors.Is(result, want) {
			t.Fatalf(
				"format-2 block=%v: expected %s, got success=%v reason=%s",
				block,
				want,
				result.Success,
				result.Reason,
			)
		}
	}
}

func TestFormat2InstrumentationExpiryMatchesChallenge(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	c, err := NewCap(CapOptions{
		Secret:              secret,
		Format:              2,
		Protocols:           []string{"instrumentation"},
		InstrumentationOpts: &InstrumentationOptions{BlockAutomatedBrowsers: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := c.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

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

	meta := wrapper.Expected[0].Instrumentation
	if meta == nil {
		t.Fatal("expected instrumentation meta")
	}

	if meta.Expires != challenge.Expires {
		t.Fatalf("expected instr expiry %d, got %d", challenge.Expires, meta.Expires)
	}
}

func TestFormat2DefaultProtocols(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	c, err := NewCap(CapOptions{Secret: secret, Format: 2})
	if err != nil {
		t.Fatal(err)
	}

	if len(c.generateOpts.Protocols) != 1 || c.generateOpts.Protocols[0] != "rsw" {
		t.Fatalf("expected [rsw], got %v", c.generateOpts.Protocols)
	}
}

func TestHashwxVectors(t *testing.T) {
	seed := sha256.Sum256([]byte("abc"))

	cases := []struct {
		nonce uint64
		want  uint64
	}{
		{0, 5739812605709599262},
		{1, 1524391919228458575},
		{196611, 645815082965079006},
		{18446744073709551615, 15368782921782672906},
	}

	for _, tc := range cases {
		got, err := HashwxHash(seed, tc.nonce)
		if err != nil {
			t.Fatal(err)
		}

		if got != tc.want {
			t.Fatalf("HashwxHash(%d) = %d, want %d", tc.nonce, got, tc.want)
		}
	}

	var zero [32]byte

	wantSeed := "2c34ce1df23b838c5abf2a7f6437cca3d3067ed509ff25f11df6b11b582b51eb"
	if got := HashwxSeed(zero[:], 0); fmt.Sprintf("%x", got) != wantSeed {
		t.Fatalf("unexpected seed: %x", got)
	}

	target, err := HashwxTarget(1000)
	if err != nil || target != 18446744073709551 {
		t.Fatalf("unexpected target: %d err=%v", target, err)
	}
}

func TestHashwxRoundTrip(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	c, err := NewCap(CapOptions{
		Secret:               secret,
		Format:               2,
		Protocols:            []string{"hashwx"},
		HashwxDifficulty:     64,
		HashwxNoncesPerHash:  16,
		HashwxChallengeCount: 4,
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := c.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	solutions := make([]V2Solution, 0, len(challenge.Challenges))

	for _, ch := range challenge.Challenges {
		if ch.Protocol != "hashwx" {
			t.Fatalf("unexpected protocol %s", ch.Protocol)
		}

		cHex, _ := ch.Payload["c"].(string)
		d, _ := ch.Payload["d"].(int)
		n, _ := ch.Payload["n"].(int)

		// Payload numbers are ints when generated in-process.
		if d == 0 {
			d = int(ch.Payload["d"].(float64))
		}

		if n == 0 {
			n = int(ch.Payload["n"].(float64))
		}

		challengeBytes, err := hexDecode(cHex)
		if err != nil {
			t.Fatal(err)
		}

		target, err := HashwxTarget(int64(d))
		if err != nil {
			t.Fatal(err)
		}

		var found uint64

		foundOK := false

		for nonce := range uint64(1_000_000) {
			seed := HashwxSeed(challengeBytes, nonce/uint64(n))

			hash, err := HashwxHash(seed, nonce)
			if err != nil {
				t.Fatal(err)
			}

			if hash <= target {
				found = nonce
				foundOK = true

				break
			}
		}

		if !foundOK {
			t.Fatal("failed to solve hashwx challenge")
		}

		solutions = append(solutions, V2Solution{Nonce: found})
	}

	result, err := c.RedeemChallenge(context.Background(), ValidateBody{
		Token:     challenge.Token,
		Solutions: SolutionsFromObjects(solutions),
	})
	if err != nil {
		t.Fatal(err)
	}

	if !result.Success {
		t.Fatalf("expected success, got %s", result.Reason)
	}

	// Invalid nonce is rejected.
	bad := make([]V2Solution, len(solutions))
	for i := range bad {
		bad[i] = V2Solution{Nonce: uint64(18446744073709551615)}
	}

	result, err = c.RedeemChallenge(context.Background(), ValidateBody{
		Token:     challenge.Token,
		Solutions: SolutionsFromObjects(bad),
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success {
		t.Fatal("expected failure with wrong nonce")
	}
}

func TestNegativeAndStringNonces(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	// Format-1 negative nonce (accepted by capjs-core).
	f1, err := generateChallengeWithContext(context.Background(), secret, GenerateOptions{
		ChallengeCount:      1,
		ChallengeSize:       8,
		ChallengeDifficulty: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	salt := prng(f1.Token+"1", 8)
	target := prng(f1.Token+"1d", 1)

	negative := int64(0)
	found := false

	for n := int64(-1); n > -100000; n-- {
		if strings.HasPrefix(sha256Hex(salt+strconv.FormatInt(n, 10)), target) {
			negative = n
			found = true

			break
		}
	}

	if !found {
		t.Fatal("failed to find a negative nonce")
	}

	result, err := validateChallengeWithContext(context.Background(), secret, ValidateBody{
		Token:     f1.Token,
		Solutions: SolutionsFromNumbers([]int64{negative}),
	}, ValidateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if !result.Success {
		t.Fatalf("expected negative nonce to pass, got %s", result.Reason)
	}

	// Format-2 leading-zero string nonce (hashed verbatim upstream).
	f2, err := generateChallengeV2(context.Background(), secret, GenerateOptions{
		Protocols:           []string{"sha256-pow"},
		ChallengeCount:      1,
		ChallengeSize:       8,
		ChallengeDifficulty: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	salt2, _ := f2.Challenges[0].Payload["salt"].(string)
	target2, _ := f2.Challenges[0].Payload["target"].(string)

	leading := ""
	found = false

	for i := range 1_000_000 {
		s := fmt.Sprintf("%08d", i)
		if strings.HasPrefix(sha256Hex(salt2+s), target2) {
			leading = s
			found = true

			break
		}
	}

	if !found {
		t.Fatal("failed to find a leading-zero nonce")
	}

	payload := jwtVerify(f2.Token, secret)

	result, err = validateChallengeV2(context.Background(), secret, ValidateBody{
		Token:     f2.Token,
		Solutions: SolutionsFromObjects([]V2Solution{{Nonce: leading}}),
	}, payload, ValidateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if !result.Success {
		t.Fatalf("expected leading-zero nonce to pass, got %s", result.Reason)
	}
}

func TestJWTSegmentStrictness(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	token := jwtSign(map[string]any{"a": 1}, secret)

	if jwtVerify(token, secret) == nil {
		t.Fatal("expected valid token to verify")
	}

	if jwtVerify(token+".extra", secret) != nil {
		t.Fatal("expected four-segment token to be rejected")
	}
}

func TestFormat2ResponseShape(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	c, err := NewCap(CapOptions{
		Secret:               secret,
		Format:               2,
		Protocols:            []string{"hashwx"},
		HashwxDifficulty:     8,
		HashwxChallengeCount: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := c.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	raw, err := json.Marshal(challenge)
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}

	if _, ok := m["challenge"]; ok {
		t.Fatalf("format-2 response must not contain challenge: %s", raw)
	}

	if m["format"] != float64(2) {
		t.Fatalf("expected format 2, got %v", m["format"])
	}

	if _, ok := m["challenges"]; !ok {
		t.Fatal("expected challenges array")
	}
}

func TestInstrumentationBlobIsExecutable(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	c, err := NewCap(CapOptions{Secret: secret, Instrumentation: true})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := c.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	blob := challenge.Instrumentation
	if blob == "" {
		t.Fatal("expected instrumentation blob")
	}

	var blobJSON any
	if err := json.Unmarshal([]byte(blob), &blobJSON); err == nil {
		t.Fatal("instrumentation blob must not be raw JSON")
	}

	compressed, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		t.Fatal(err)
	}

	r := flate.NewReader(bytes.NewReader(compressed))
	defer func() { _ = r.Close() }()

	script, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	needles := []string{"postMessage", "fontWidths", "outerWidth", "native code", "cap:instr"}
	for _, want := range needles {
		if !strings.Contains(string(script), want) {
			t.Fatalf("script missing %q", want)
		}
	}
}

func hexDecode(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := range out {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, err
		}

		out[i] = byte(v)
	}

	return out, nil
}

func containsString(s []string, want string) bool {
	return slices.Contains(s, want)
}

func TestValidateTokenWithTokenKey(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")
	store := NewMemoryStorage()

	c, err := NewCap(CapOptions{
		Secret:              secret,
		Storage:             store,
		ChallengeCount:      1,
		ChallengeSize:       4,
		ChallengeDifficulty: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := c.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	solutions := solveChallenge(challenge.Token, 1, 4, 1)

	result, err := c.RedeemChallenge(context.Background(), ValidateBody{
		Token:     challenge.Token,
		Solutions: SolutionsFromNumbers(solutions),
	})
	if err != nil {
		t.Fatal(err)
	}

	if !result.Success {
		t.Fatalf("redeem failed: %s", result.Reason)
	}

	if vt := c.ValidateToken(context.Background(), result.Token); !vt.Success {
		t.Fatalf("token lookup failed: %s", vt.Reason)
	}

	if result.TokenKey != nil {
		if vt := c.ValidateToken(context.Background(), *result.TokenKey); !vt.Success {
			t.Fatalf("tokenKey lookup failed: %s", vt.Reason)
		}
	}
}

func TestFormat2MissingSolutionsReason(t *testing.T) {
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

	result, err := validateChallengeV2(context.Background(), secret, ValidateBody{
		Token: challenge.Token,
	}, payload, ValidateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if result.Success || result.Reason != "missing_solutions" {
		t.Fatalf(
			"expected missing_solutions, got success=%v reason=%s",
			result.Success,
			result.Reason,
		)
	}
}

func TestFormat1InstrumentationExpiryMatchesChallenge(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	c, err := NewCap(CapOptions{Secret: secret, Instrumentation: true})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := c.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	payload := jwtVerify(challenge.Token, secret)
	ei, _ := payload["ei"].(string)

	meta := instrumentationMetaFromEncrypted(ei, secret)
	if meta == nil {
		t.Fatal("expected instrumentation meta")
	}

	if meta.Expires != challenge.Expires {
		t.Fatalf("expected instr expiry %d, got %d", challenge.Expires, meta.Expires)
	}
}

func TestRswPrebuiltMinter(t *testing.T) {
	secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

	kp, err := GenerateRswKeypair(512)
	if err != nil {
		t.Fatal(err)
	}

	minter, err := BuildRswMinter(struct {
		N *big.Int
		P *big.Int
		Q *big.Int
		T int
		G *big.Int
	}{N: kp.N, P: kp.P, Q: kp.Q, T: 1000})
	if err != nil {
		t.Fatal(err)
	}

	c, err := NewCap(CapOptions{
		Secret:    secret,
		Format:    2,
		Protocols: []string{"rsw"},
		Rsw:       minter,
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := c.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if got := challenge.Challenges[0].Payload["t"]; got != 1000 {
		t.Fatalf("expected t=1000, got %v", got)
	}

	if got := challenge.Challenges[0].Payload["N"]; got != minter.N_hex {
		t.Fatalf("expected N=%s, got %v", minter.N_hex, got)
	}
}

func TestValidateBodyOfficialShape(t *testing.T) {
	format1 := ValidateBody{
		Token:     "t",
		Solutions: NumberSolutions(1, 2),
	}

	raw, err := json.Marshal(format1)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(raw), "v2Sol") || strings.Contains(string(raw), "Numbers") {
		t.Fatalf("unexpected legacy/marshal artifacts: %s", raw)
	}

	if !strings.Contains(string(raw), `"solutions":[1,2]`) {
		t.Fatalf("unexpected format-1 body: %s", raw)
	}

	format2 := ValidateBody{
		Token:     "t",
		Solutions: ObjectSolutions(V2Solution{Nonce: 5}, V2Solution{Y: "abc"}),
	}

	raw, err = json.Marshal(format2)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(raw), `"solutions":[{"nonce":5},{"y":"abc"}]`) {
		t.Fatalf("unexpected format-2 body: %s", raw)
	}

	var decoded ValidateBody

	body2 := []byte(`{"token":"t","solutions":[{"nonce":5}]}`)
	if err := json.Unmarshal(body2, &decoded); err != nil {
		t.Fatal(err)
	}

	if len(decoded.Solutions.Objects) != 1 || decoded.Solutions.Numbers != nil {
		t.Fatalf("expected object solutions, got %+v", decoded.Solutions)
	}

	emptyBody := ValidateBody{Token: "t"}

	raw, err = json.Marshal(emptyBody)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(raw), "solutions") {
		t.Fatalf("expected zero solutions to be omitted, got %s", raw)
	}

	// The legacy gocap-only field is not recognised anymore.
	var legacy ValidateBody

	bodyLegacy := []byte(`{"token":"t","v2Sol":[{"nonce":5}]}`)
	if err := json.Unmarshal(bodyLegacy, &legacy); err != nil {
		t.Fatal(err)
	}

	if !legacy.Solutions.IsZero() {
		t.Fatalf("expected v2Sol to be ignored, got %+v", legacy.Solutions)
	}
}
