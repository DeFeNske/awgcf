package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

type AmneziaVersion string

const (
	AWG2  AmneziaVersion = "awg2"
	AWG3  AmneziaVersion = "awg3"
	AWG31 AmneziaVersion = "awg3.1"
)

type AmneziaConfig struct {
	Version AmneziaVersion `json:"version"`

	Jc   uint16 `json:"jc"`
	Jmin uint16 `json:"jmin"`
	Jmax uint16 `json:"jmax"`

	S1 uint16 `json:"s1"`
	S2 uint16 `json:"s2"`
	S3 uint16 `json:"s3"`
	S4 uint16 `json:"s4"`

	H1 string `json:"h1"`
	H2 string `json:"h2"`
	H3 string `json:"h3"`
	H4 string `json:"h4"`

	I1 string `json:"i1,omitempty"`
	I2 string `json:"i2,omitempty"`
	I3 string `json:"i3,omitempty"`
	I4 string `json:"i4,omitempty"`
	I5 string `json:"i5,omitempty"`

	HeaderProtectionKey    string `json:"header_protection_key,omitempty"`
	ContentPaddingAddition string `json:"content_padding_addition,omitempty"`

	RekeyAfterTime       string `json:"rekey_after_time,omitempty"`
	RekeyTimeout         string `json:"rekey_timeout,omitempty"`
	RejectAfterTime      string `json:"reject_after_time,omitempty"`
	KeepaliveTimeout     string `json:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts string `json:"max_handshake_attempts,omitempty"`

	RandomTrailers bool `json:"random_trailers,omitempty"`
	DisableCookies bool `json:"disable_cookies,omitempty"`
}

// NewRandomAmneziaConfig creates a valid client-side AWG configuration.
// For compatibility with a stock WireGuard/WARP peer, S1-S4 remain 0 and
// H1-H4 remain the standard WireGuard message types. Jc/Jmin/Jmax and I1-I5
// are client-side-only obfuscation parameters.
func NewRandomAmneziaConfig(version AmneziaVersion) (*AmneziaConfig, error) {
	if version == "" {
		version = AWG2
	}
	if version != AWG2 && version != AWG3 && version != AWG31 {
		return nil, fmt.Errorf("unsupported AmneziaWG version %q", version)
	}

	jc, err := randomUint16(4, 12)
	if err != nil {
		return nil, err
	}
	jmin, err := randomUint16(32, 96)
	if err != nil {
		return nil, err
	}
	jmax, err := randomUint16(jmin+32, 256)
	if err != nil {
		return nil, err
	}

	cfg := &AmneziaConfig{
		Version: version,
		Jc:      jc,
		Jmin:    jmin,
		Jmax:    jmax,
		// These values preserve WireGuard compatibility. Non-zero S/H
		// values require the same values on the peer.
		S1: 0, S2: 0, S3: 0, S4: 0,
		H1: "1", H2: "2", H3: "3", H4: "4",
	}

	// I1 is deliberately client-side only. The random-byte CPS tag is
	// supported by AmneziaWG and does not need to be mirrored by the server.
	n, err := randomUint16(16, 64)
	if err != nil {
		return nil, err
	}
	cfg.I1 = fmt.Sprintf("<r %d>", n)

	// 3.0/3.1 fields are left disabled by default because HeaderProtectionKey
	// is a server-side value and ContentPadding/Timing parameters may need to
	// match the server. The version is still emitted in the generated profile.
	if version == AWG31 {
		// Keep these off unless explicitly supplied by --config.
		cfg.RandomTrailers = false
		cfg.DisableCookies = false
	}

	return cfg, nil
}

func LoadAmneziaConfig(path string) (*AmneziaConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read AWG config %q: %w", path, err)
	}

	var cfg AmneziaConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse AWG config %q: %w", path, err)
	}

	if cfg.Version == "" {
		cfg.Version = AWG2
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *AmneziaConfig) Validate() error {
	if c.Version != AWG2 && c.Version != AWG3 && c.Version != AWG31 {
		return fmt.Errorf("unsupported AmneziaWG version %q", c.Version)
	}
	if c.Jc > 128 {
		return fmt.Errorf("Jc must be <= 128")
	}
	if c.Jmin > c.Jmax {
		return fmt.Errorf("Jmin must be <= Jmax")
	}
	if c.Jmax >= 1280 {
		return fmt.Errorf("Jmax must be below 1280 to avoid fragmentation with MTU 1280")
	}
	if c.Version == AWG2 && (c.HeaderProtectionKey != "" || c.ContentPaddingAddition != "" ||
		c.RekeyAfterTime != "" || c.RekeyTimeout != "" || c.RejectAfterTime != "" ||
		c.KeepaliveTimeout != "" || c.MaxHandshakeAttempts != "" ||
		c.RandomTrailers || c.DisableCookies) {
		return fmt.Errorf("AWG 2.0 config contains AWG 3.x-only parameters")
	}
	if c.Version == AWG3 && (c.RandomTrailers || c.DisableCookies) {
		return fmt.Errorf("RandomTrailers and DisableCookies require AWG 3.1")
	}
	return nil
}

func randomUint16(min, max uint16) (uint16, error) {
	if min > max {
		return 0, fmt.Errorf("invalid random range %d-%d", min, max)
	}
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	v := uint32(b[0])<<8 | uint32(b[1])
	return uint16(uint32(min) + v%(uint32(max)-uint32(min)+1)), nil
}

// RandomHeaderProtectionKey returns a base64-encoded 32-byte AWG header key.
func RandomHeaderProtectionKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// RandomHexBytes is useful when constructing CPS <b 0x...> values.
func RandomHexBytes(n int) (string, error) {
	if n < 0 {
		return "", fmt.Errorf("negative byte count")
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
