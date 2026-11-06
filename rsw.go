package gocap

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
)

// RswKeypair holds the RSA-style modulus and its prime factors for RSW
// time-lock puzzles. Generate once at startup with GenerateRswKeypair and
// reuse across requests. Keep the private factors (P, Q) secret.
type RswKeypair struct {
	N    *big.Int
	P    *big.Int
	Q    *big.Int
	Bits int
}

// SerializedRswKeypair is a JSON-safe representation of RswKeypair, suitable
// for storing in environment variables, config files, or databases.
type SerializedRswKeypair struct {
	N    string `json:"N"`
	P    string `json:"p"`
	Q    string `json:"q"`
	Bits int    `json:"bits,omitzero"`
}

// RswMinter creates RSW time-lock puzzle challenges using repeated squaring.
// Build one with BuildRswMinter and reuse it for multiple Mint calls.
type RswMinter struct {
	N *big.Int
	G *big.Int
	H *big.Int

	p     *big.Int
	q     *big.Int
	N_hex string
	G_hex string
	H_hex string

	T            int
	ModulusBytes int
}

// RswMintResult is the output of a single RSW mint operation.
// X_hex is the challenge value sent to the client; Y_hex is the expected
// solution kept server-side.
type RswMintResult struct {
	X_hex string `json:"x_hex"`
	Y_hex string `json:"y_hex"`
}

func bigintFromBuf(buf []byte) *big.Int {
	return new(big.Int).SetBytes(buf)
}

func modpow(b, e, m *big.Int) *big.Int {
	return new(big.Int).Exp(b, e, m)
}

func modinv(a, m *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, m)
}

func randomPrime(bits int) (*big.Int, error) {
	return rand.Prime(rand.Reader, bits)
}

// GenerateRswKeypair generates an RSA-style keypair with the given bit size
// for use with RSW time-lock puzzles. bits must be even; default is 2048.
// Generation is expensive (hundreds of milliseconds to seconds); generate
// once at startup and reuse.
func GenerateRswKeypair(bits ...int) (*RswKeypair, error) {
	b := 2048
	if len(bits) > 0 {
		b = bits[0]
	}

	if b%2 != 0 {
		return nil, ErrRSWBitsMustBeEven
	}

	halfBits := b / 2

	p, err := randomPrime(halfBits)
	if err != nil {
		return nil, err
	}

	var q *big.Int
	for {
		q, err = randomPrime(halfBits)
		if err != nil {
			return nil, err
		}

		if q.Cmp(p) != 0 {
			break
		}
	}

	N := new(big.Int).Mul(p, q)

	return &RswKeypair{N: N, P: p, Q: q, Bits: b}, nil
}

// SerializeRswKeypair serializes a keypair for JSON storage or transmission.
// The returned struct uses decimal string encoding for big integers.
func SerializeRswKeypair(kp *RswKeypair) *SerializedRswKeypair {
	return &SerializedRswKeypair{
		N:    kp.N.String(),
		P:    kp.P.String(),
		Q:    kp.Q.String(),
		Bits: kp.Bits,
	}
}

// DeserializeRswKeypair restores a keypair from its serialized form.
// Returns an error if the serialized data is nil or contains invalid big
// integer strings.
func DeserializeRswKeypair(s *SerializedRswKeypair) (*RswKeypair, error) {
	if s == nil {
		return nil, errors.New("invalid serialized rsw keypair")
	}

	N, ok1 := new(big.Int).SetString(s.N, 10)
	P, ok2 := new(big.Int).SetString(s.P, 10)

	Q, ok3 := new(big.Int).SetString(s.Q, 10)
	if !ok1 || !ok2 || !ok3 {
		return nil, errors.New("rsw keypair fields must be valid big integers")
	}

	bits := s.Bits
	if bits == 0 {
		bits = N.BitLen()
	}

	return &RswKeypair{N: N, P: P, Q: Q, Bits: bits}, nil
}

func hexOf(bi *big.Int, byteLen int) string {
	s := hex.EncodeToString(bi.Bytes())

	if byteLen > 0 {
		target := byteLen * 2
		if len(s) < target {
			s = strings.Repeat("0", target-len(s)) + s
		}
	}

	return s
}

// BuildRswMinter builds a minter that creates RSW puzzles using the given
// keypair and squaring count t. The minter uses CRT-optimized modular
// exponentiation for efficient puzzle generation.
func BuildRswMinter(args struct {
	N *big.Int
	P *big.Int
	Q *big.Int
	T int
	G *big.Int
},
) (*RswMinter, error) {
	if args.N == nil || args.P == nil || args.Q == nil {
		return nil, errors.New("rsw minter needs N, P, Q")
	}

	if args.T <= 0 {
		return nil, errors.New("rsw minter needs t > 0")
	}

	bits := args.N.BitLen()
	modulusBytes := (bits + 7) / 8

	G := args.G
	if G == nil {
		max := new(big.Int).Sub(args.N, big.NewInt(3))

		randInt, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, err
		}

		G = new(big.Int).Add(randInt, big.NewInt(2))
	}

	pm1 := new(big.Int).Sub(args.P, big.NewInt(1))
	qm1 := new(big.Int).Sub(args.Q, big.NewInt(1))
	e_p := modpow(big.NewInt(2), big.NewInt(int64(args.T)), pm1)
	e_q := modpow(big.NewInt(2), big.NewInt(int64(args.T)), qm1)
	hp := modpow(new(big.Int).Mod(G, args.P), e_p, args.P)
	hq := modpow(new(big.Int).Mod(G, args.Q), e_q, args.Q)
	qinv_p := modinv(new(big.Int).Mod(args.Q, args.P), args.P)

	crtCombine := func(ap, aq *big.Int) *big.Int {
		p := args.P
		q := args.Q
		diff := new(big.Int).Sub(ap, aq)
		diff.Mod(diff, p)

		if diff.Sign() < 0 {
			diff.Add(diff, p)
		}

		s := new(big.Int).Mul(diff, qinv_p)
		s.Mod(s, p)

		return new(big.Int).Add(aq, new(big.Int).Mul(q, s))
	}
	h := crtCombine(hp, hq)

	return &RswMinter{
		N:            args.N,
		T:            args.T,
		G:            G,
		H:            h,
		ModulusBytes: modulusBytes,
		N_hex:        hexOf(args.N, modulusBytes),
		G_hex:        hexOf(G, modulusBytes),
		H_hex:        hexOf(h, modulusBytes),
		p:            args.P,
		q:            args.Q,
	}, nil
}

// Mint creates a new RSW puzzle and returns the challenge x_hex and
// expected solution y_hex. The caller sends x_hex to the client and keeps
// y_hex server-side for later verification.
func (m *RswMinter) Mint() (*RswMintResult, error) {
	rBytes := make([]byte, 32)
	if _, err := rand.Read(rBytes); err != nil {
		return nil, err
	}

	r := bigintFromBuf(rBytes)
	pm1 := new(big.Int).Sub(m.p, big.NewInt(1))
	qm1 := new(big.Int).Sub(m.q, big.NewInt(1))
	rp := new(big.Int).Mod(r, pm1)
	rq := new(big.Int).Mod(r, qm1)
	gp := new(big.Int).Mod(m.G, m.p)
	gq := new(big.Int).Mod(m.G, m.q)
	hp := new(big.Int).Mod(m.H, m.p)
	hq := new(big.Int).Mod(m.H, m.q)
	xp := modpow(gp, rp, m.p)
	xq := modpow(gq, rq, m.q)
	yp := modpow(hp, rp, m.p)
	yq := modpow(hq, rq, m.q)
	qinv_p := modinv(new(big.Int).Mod(m.q, m.p), m.p)
	crtCombine := func(ap, aq *big.Int) *big.Int {
		p := m.p
		q := m.q
		diff := new(big.Int).Sub(ap, aq)
		diff.Mod(diff, p)

		if diff.Sign() < 0 {
			diff.Add(diff, p)
		}

		s := new(big.Int).Mul(diff, qinv_p)
		s.Mod(s, p)

		return new(big.Int).Add(aq, new(big.Int).Mul(q, s))
	}
	x := crtCombine(xp, xq)
	y := crtCombine(yp, yq)

	return &RswMintResult{
		X_hex: hexOf(x, m.ModulusBytes),
		Y_hex: hexOf(y, m.ModulusBytes),
	}, nil
}

// VerifyRswSolution verifies that the claimed y solution matches the
// expected y. Comparison is case-insensitive and ignores leading zeros
// and optional 0x prefix.
func VerifyRswSolution(expectedYHex, claimedYHex string) bool {
	norm := func(s string) string {
		s = strings.TrimPrefix(s, "0x")
		s = strings.ToLower(s)
		s = strings.TrimLeft(s, "0")

		return s
	}

	return norm(expectedYHex) == norm(claimedYHex)
}
