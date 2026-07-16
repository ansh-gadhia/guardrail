package security

// RefreshGenerator implements iam.RefreshTokenGenerator.
type RefreshGenerator struct{}

// NewRefreshGenerator constructs a RefreshGenerator.
func NewRefreshGenerator() *RefreshGenerator { return &RefreshGenerator{} }

// Generate returns a new opaque refresh token and its storage hash.
func (RefreshGenerator) Generate() (string, []byte, error) { return GenerateRefreshToken() }

// Hash hashes a raw refresh token for lookup.
func (RefreshGenerator) Hash(raw string) []byte { return HashRefreshToken(raw) }
