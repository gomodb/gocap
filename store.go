package gocap

import (
	"context"
	"sync"
	"time"
)

// Storage is the persistence interface for challenge and validation tokens.
// Implementations must be safe for concurrent use.
//
// All methods receive a context.Context for cancellation and tracing.
// Expired entries should be removed lazily via CleanupExpired.
type Storage interface {
	// SetChallengeToken stores a challenge token with its expiration time.
	SetChallengeToken(ctx context.Context, token string, expiresAt time.Time) error

	// GetChallengeTokenExpiry returns the expiration time for a stored
	// challenge token. The bool indicates whether the token was found.
	GetChallengeTokenExpiry(ctx context.Context, token string) (time.Time, bool, error)

	// SetValidationToken stores a validation token with its expiration time.
	SetValidationToken(ctx context.Context, token string, expiresAt time.Time) error

	// GetValidationTokenExpiry returns the expiration time for a stored
	// validation token. The bool indicates whether the token was found.
	GetValidationTokenExpiry(ctx context.Context, token string) (time.Time, bool, error)

	// CleanupExpired removes expired challenge and validation tokens.
	CleanupExpired(ctx context.Context) error
}

// MemoryStorage is an in-memory Storage implementation backed by maps.
// Concurrent reads use RLock; writes and cleanup use an exclusive Lock.
// Suitable for development and testing; for production, use a persistent
// backend via the Storage interface.
type MemoryStorage struct {
	mu               sync.RWMutex
	challengeTokens  map[string]time.Time
	validationTokens map[string]time.Time
}

// NewMemoryStorage creates a new in-memory Storage implementation.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		challengeTokens:  make(map[string]time.Time),
		validationTokens: make(map[string]time.Time),
	}
}

// SetChallengeToken stores a challenge token in memory.
func (s *MemoryStorage) SetChallengeToken(
	_ context.Context,
	token string,
	expiresAt time.Time,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.challengeTokens[token] = expiresAt

	return nil
}

// GetChallengeTokenExpiry returns a stored challenge token's expiration time.
func (s *MemoryStorage) GetChallengeTokenExpiry(
	_ context.Context,
	token string,
) (time.Time, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	expiresAt, ok := s.challengeTokens[token]

	return expiresAt, ok, nil
}

// SetValidationToken stores a validation token in memory.
func (s *MemoryStorage) SetValidationToken(
	_ context.Context,
	token string,
	expiresAt time.Time,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.validationTokens[token] = expiresAt

	return nil
}

// GetValidationTokenExpiry returns a stored validation token's expiration time.
func (s *MemoryStorage) GetValidationTokenExpiry(
	_ context.Context,
	token string,
) (time.Time, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	expiresAt, ok := s.validationTokens[token]

	return expiresAt, ok, nil
}

// CleanupExpired removes expired entries from the in-memory store.
func (s *MemoryStorage) CleanupExpired(_ context.Context) error {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	for k, expires := range s.challengeTokens {
		if !expires.After(now) {
			delete(s.challengeTokens, k)
		}
	}

	for k, expires := range s.validationTokens {
		if !expires.After(now) {
			delete(s.validationTokens, k)
		}
	}

	return nil
}
