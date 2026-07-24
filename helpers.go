package gocap

import (
	"fmt"
	"maps"
	"time"
)

// res creates a ValidateResult with Success=false using a sentinel error.
// The Reason is set from err.Error() and err is stored for Unwrap().
func res(err error) ValidateResult {
	return ValidateResult{Success: false, Reason: err.Error(), err: err}
}

// failInstrErr creates a failure result from a sentinel instrumentation error.
func failInstrErr(err error) ValidateResult {
	return ValidateResult{Success: false, Reason: err.Error(), InstrErr: true, err: err}
}

func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint:
		return int64(n), true
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		if n > ^uint64(0)>>1 {
			return 0, false
		}

		return int64(n), true
	case float64:
		if n != float64(int64(n)) {
			return 0, false
		}

		return int64(n), true
	case float32:
		f := float64(n)
		if f != float64(int64(f)) {
			return 0, false
		}

		return int64(f), true
	default:
		return 0, false
	}
}

func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}

	out := make(map[string]any, len(m))
	maps.Copy(out, m)

	return out
}

func clampChallengeOptions(opts GenerateOptions) (int, int, int, time.Duration, error) {
	c := opts.ChallengeCount
	if c == 0 {
		c = defaultChallengeCount
	}

	s := opts.ChallengeSize
	if s == 0 {
		s = defaultChallengeSize
	}

	d := opts.ChallengeDifficulty
	if d == 0 {
		d = defaultChallengeDifficulty
	}

	ttl := opts.Expires
	if ttl <= 0 {
		ttl = defaultChallengeTTL
	}

	if c < 1 || c > maxChallengeCount || s < 1 || s > maxChallengeSize || d < 1 ||
		d > maxChallengeDifficulty {
		return 0, 0, 0, 0, fmt.Errorf(
			"invalid params: c≤%d, s≤%d, d∈[1,%d]",
			maxChallengeCount,
			maxChallengeSize,
			maxChallengeDifficulty,
		)
	}

	return c, s, d, ttl, nil
}

// v2ExpectedEntry is an internal struct for the encrypted expected values in format-2.
type v2ExpectedEntry struct {
	Protocol        string               `json:"protocol"`
	Salt            string               `json:"salt,omitzero"`
	Target          string               `json:"target,omitzero"`
	Y               string               `json:"y,omitzero"`
	Instrumentation *InstrumentationMeta `json:"instrMeta,omitzero"`
}
