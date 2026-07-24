package gocap

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"time"
)

// InstrumentationMeta holds the metadata needed to verify a client-side
// instrumentation result. It is encrypted and embedded in the JWT payload
// when instrumentation is enabled.
type InstrumentationMeta struct {
	ID                     string   `json:"id"`
	ExpectedVals           []int    `json:"expectedVals"`
	Vars                   []string `json:"vars"`
	BlockAutomatedBrowsers bool     `json:"blockAutomatedBrowsers"`
	Expires                int64    `json:"expires"`
}

// InstrumentationResult is the client-side instrumentation result payload,
// submitted back to the server for verification.
type InstrumentationResult struct {
	// I is the instrumentation challenge ID, matching InstrumentationMeta.ID.
	I string `json:"i"`
	// State maps each variable name to its computed client-side value.
	State map[string]int `json:"state"`
	// Ts is the client timestamp in Unix milliseconds.
	Ts int64 `json:"ts,omitzero"`
}

// InstrumentationOptions configures instrumentation generation behaviour.
type InstrumentationOptions struct {
	// BlockAutomatedBrowsers, when true, causes the server to reject
	// requests where the instrumentation was blocked.
	BlockAutomatedBrowsers bool
	// ObfuscationLevel controls the complexity of client-side code
	// obfuscation (1-10, default 3). Higher values produce more
	// obfuscated but larger scripts.
	ObfuscationLevel int
	// TTLMs is the instrumentation challenge lifetime in milliseconds.
	// Defaults to 5 minutes when not set.
	TTLMs int64
}

func fastRnd(a, b int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(b-a+1)))
	if err != nil {
		return 0, err
	}

	return a + int(n.Int64()), nil
}

var (
	varLetters = "abcdefghijklmnopqrstuvwxyz"
	varChars   = "abcdefghijklmnopqrstuvwxyz0123456789"
)

func rVar(length int) string {
	if length <= 0 {
		length = 8
	}

	b := make([]byte, length)
	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(varLetters))))

	b[0] = varLetters[idx.Int64()]
	for i := 1; i < length; i++ {
		idx, _ = rand.Int(rand.Reader, big.NewInt(int64(len(varChars))))
		b[i] = varChars[idx.Int64()]
	}

	return string(b)
}

func toInt32(n int) int {
	return int(int32(n))
}

func rHex(length int) (string, error) {
	b := make([]byte, (length+1)/2)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	s := ""
	for _, bb := range b {
		s += string("0123456789abcdef"[bb>>4])
		if len(s) >= length {
			break
		}

		s += string("0123456789abcdef"[bb&0xf])
	}

	return s[:length], nil
}

// GenerateInstrumentation generates random instrumentation parameters.
// It returns the metadata (to be encrypted and embedded in the JWT) and a
// JSON blob describing the parameters for the client-side widget.
func GenerateInstrumentation(opts InstrumentationOptions) (*InstrumentationMeta, string, error) {
	id, err := rHex(32)
	if err != nil {
		return nil, "", err
	}

	vars := make([]string, 4)
	initVals := make([]int, 4)

	for i := range 4 {
		vars[i] = rVar(12)

		initVals[i], err = fastRnd(10, 250)
		if err != nil {
			return nil, "", err
		}
	}

	vals := make([]int, 4)
	copy(vals, initVals)

	blockAutomatedBrowsers := opts.BlockAutomatedBrowsers

	correctKey, err := fastRnd(1000, 9000)
	if err != nil {
		return nil, "", err
	}

	badKey, err := fastRnd(1000, 9000)
	if err != nil {
		return nil, "", err
	}

	for badKey == correctKey {
		badKey, err = fastRnd(1000, 9000)
		if err != nil {
			return nil, "", err
		}
	}

	vals[0] = toInt32(vals[0] ^ correctKey)

	for range 20 {
		op, err := fastRnd(0, 5)
		if err != nil {
			return nil, "", err
		}

		dest, err := fastRnd(0, 3)
		if err != nil {
			return nil, "", err
		}

		src1, err := fastRnd(0, 3)
		if err != nil {
			return nil, "", err
		}

		src2, err := fastRnd(0, 3)
		if err != nil {
			return nil, "", err
		}

		src3, err := fastRnd(0, 3)
		if err != nil {
			return nil, "", err
		}

		vD := vals[dest]
		vS1 := vals[src1]
		vS2 := vals[src2]

		switch op {
		case 0:
			vals[dest] = toInt32(^(vD & vS1))
		case 1:
			vals[dest] = toInt32(vD ^ vS1)
		case 2:
			vals[dest] = toInt32(vD | vS1)
		case 3:
			vals[dest] = toInt32(vD & vS1)
		case 4:
			vals[dest] = toInt32((vS2 ^ vS1) | (vD ^ vS2))
		case 5:
			vals[dest] = toInt32(domSumMock(vals[src1], vals[src2], vals[src3]))
		}
	}

	salts := make([]int, 4)
	for i := range 4 {
		salts[i], err = fastRnd(100000, 999999)
		if err != nil {
			return nil, "", err
		}

		vals[i] = (((vals[i] ^ salts[i]) & 0x7fffffff) % 900000) + 100000
	}

	ttlMs := opts.TTLMs
	if ttlMs <= 0 {
		ttlMs = 5 * 60 * 1000
	}

	meta := &InstrumentationMeta{
		ID:                     id,
		ExpectedVals:           vals,
		Vars:                   vars,
		BlockAutomatedBrowsers: blockAutomatedBrowsers,
		Expires:                time.Now().UnixMilli() + ttlMs,
	}
	params := map[string]any{
		"id": id, "vars": vars, "initVals": initVals,
		"correctKey": correctKey, "badKey": badKey,
		"salts": salts, "block": blockAutomatedBrowsers,
	}
	paramsJSON, _ := json.Marshal(params)

	return meta, string(paramsJSON), nil
}

// VerifyInstrumentationResult checks whether the client's instrumentation
// response is valid. It verifies that the ID matches and that each variable
// in the client's state has the expected value.
func VerifyInstrumentationResult(
	meta *InstrumentationMeta,
	payload *InstrumentationResult,
) (bool, string) {
	if meta == nil {
		return false, "missing_meta"
	}

	if payload == nil {
		return false, "missing_output"
	}

	if payload.I != meta.ID {
		return false, "id_mismatch"
	}

	state := payload.State
	if state == nil {
		return false, "invalid_state"
	}

	if len(meta.Vars) == 0 || len(meta.ExpectedVals) == 0 {
		return false, "invalid_meta"
	}

	if len(meta.Vars) != len(meta.ExpectedVals) {
		return false, "invalid_meta"
	}

	for i, v := range meta.Vars {
		if state[v] != meta.ExpectedVals[i] {
			return false, "failed_challenge"
		}
	}

	return true, ""
}

// domSumMock simulates the client-side DOM-based helper function for
// deterministic testability. It mirrors the widget's DOM manipulation
// without an actual browser environment.
func domSumMock(x, y, z int) int {
	type node struct {
		parentNode *node
		innerText  int
		isRoot     bool
	}

	root := &node{isRoot: true}
	buildChain := func(parent *node, val int) *node {
		cur := parent

		v := val
		for range 8 {
			child := &node{parentNode: cur, innerText: v}
			if v&1 == 0 {
				cur = child
			}

			v >>= 1
		}

		return cur
	}

	var walk func(n *node, rootRef *node, sum int) int

	walk = func(n *node, rootRef *node, sum int) int {
		if n == nil || n == rootRef {
			return sum % 256
		}

		return walk(n.parentNode, rootRef, sum+n.innerText)
	}

	return toInt32(walk(buildChain(buildChain(buildChain(root, x), y), z), root, 0))
}

// instrumentationMetaFromEncrypted decrypts and parses an encrypted
// instrumentation metadata blob from the JWT payload "ei" field.
func instrumentationMetaFromEncrypted(blob string, secret []byte) *InstrumentationMeta {
	data, ok := decryptGcmRaw(blob, secret)
	if !ok {
		return nil
	}

	var meta InstrumentationMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil
	}

	return &meta
}

// encodeInstrumentationMeta encrypts instrumentation metadata for embedding
// in the JWT payload "ei" field.
func encodeInstrumentationMeta(meta *InstrumentationMeta, secret []byte) (string, error) {
	return encryptGcm(meta, secret)
}
