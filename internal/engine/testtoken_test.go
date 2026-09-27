package engine

// fakeToken builds a synthetic secret value at runtime out of an algorithm and
// a small alphabet, never a literal secret-looking string, so that gitleaks
// and GitGuardian do not flag this repository's own test fixtures. It is a
// deterministic PRNG (xorshift32, fixed seed), so results are stable across
// runs, which the determinism tests below depend on.
func fakeToken(prefix string, n int) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	x := uint32(0x2545F491)
	b := make([]byte, n)
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = alphabet[x%uint32(len(alphabet))]
	}
	return prefix + string(b)
}

// githubPAT returns a synthetic value matching gitleaks' built-in
// "github-pat" rule (ghp_ + 36 alphanumeric characters, entropy >= 3).
func githubPAT() string {
	return fakeToken("gh"+"p_", 36)
}
