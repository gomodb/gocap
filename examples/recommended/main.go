// Command recommended shows a security-first gocap configuration:
// HashWX proof of work plus instrumentation.
//
// ConsumeNonce is a placeholder that fails closed. In production, implement
// one-time consumption (for example Redis SET NX EX) and return true only for
// the first use of a challenge signature.
package main

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/gomodb/gocap"
)

func main() {
	secret := []byte("replace-with-a-32-byte-high-entropy-secret")

	// Optional: compile the embedded HashWX wasm before the first request.
	if err := gocap.HashwxReady(); err != nil {
		log.Fatal(err)
	}

	capInstance, err := gocap.NewCap(gocap.CapOptions{
		Secret:  secret,
		Storage: gocap.NewMemoryStorage(), // production: Redis/PostgreSQL implementation

		Format:    2,
		Protocols: []string{"hashwx", "instrumentation"},

		HashwxDifficulty:     1_000_000,
		HashwxChallengeCount: 4,
		HashwxNoncesPerHash:  65_536,

		InstrumentationOpts: &gocap.InstrumentationOptions{
			BlockAutomatedBrowsers: true, // roll out after watching riskFlags
			ObfuscationLevel:       3,
		},

		ChallengeTTL: 10 * time.Minute,
		TokenTTL:     20 * time.Minute,

		ConsumeNonce: func(context.Context, string, time.Duration) (bool, error) {
			return false, errors.New("implement ConsumeNonce with Redis SET NX EX")
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	challenge, err := capInstance.CreateChallenge(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	log.Printf(
		"challenge created: protocols=%d token_len=%d expires=%d",
		len(challenge.Challenges),
		len(challenge.Token),
		challenge.Expires,
	)
}
