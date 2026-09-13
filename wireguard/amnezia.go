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

// Known working CPS signature used by the generated WARP profiles.
const defaultI1 = `<b 0xce000000010897a297ecc34cd6dd000044d0ec2e2e1ea2991f467ace4222129b5a098823784694b4897b9986ae0b7280135fa85e196d9ad980b150122129ce2a9379531b0fd3e871ca5fdb883c369832f730e272d7b8b74f393f9f0fa43f11e510ecb2219a52984410c204cf875585340c62238e14ad04dff382f2c200e0ee22fe743b9c6b8b043121c5710ec289f471c91ee414fca8b8be8419ae8ce7ffc53837f6ade262891895f3f4cecd31bc93ac5599e18e4f01b472362b8056c3172b513051f8322d1062997ef4a383b01706598d08d48c221d30e74c7ce000cdad36b706b1bf9b0607c32ec4b3203a4ee21ab64df336212b9758280803fcab14933b0e7ee1e04a7becce3e2633f4852585c567894a5f9efe9706a151b615856647e8b7dba69ab357b3982f554549bef9256111b2d67afde0b496f16962d4957ff654232aa9e845b61463908309cfd9de0a6abf5f425f577d7e5f6440652aa8da5f73588e82e9470f3b21b27b28c649506ae1a7f5f15b876f56abc4615f49911549b9bb39dd804fde182bd2dcec0c33bad9b138ca07d4a4a1650a2c2686acea05727e2a78962a840ae428f55627516e73c83dd8893b02358e81b524b4d99fda6df52b3a8d7a5291326e7ac9d773c5b43b8444554ef5aea104a738ed650aa979674bbed38da58ac29d87c29d387d80b526065baeb073ce65f075ccb56e47533aef357dceaa8293a523c5f6f790be90e4731123d3c6152a70576e90b4ab5bc5ead01576c68ab633ff7d36dcde2a0b2c68897e1acfc4d6483aaaeb635dd63c96b2b6a7a2bfe042f6aed82e5363aa850aace12ee3b1a93f30d8ab9537df483152a5527faca21efc9981b304f11fc95336f5b9637b174c5a0659e2b22e159a9fed4b8e93047371175b1d6d9cc8ab745f3b2281537d1c75fb9451871864efa5d184c38c185fd203de206751b92620f7c369e031d2041e152040920ac2c5ab5340bfc9d0561176abf10a147287ea90758575ac6a9f5ac9f390d0d5b23ee12af583383d994e22c0cf42383834bcd3ada1b3825a0664d8f3fb678261d57601ddf94a8a68a7c273a18c08aa99c7ad8c6c42eab67718843597ec9930457359dfdfbce024afc2dcf9348579a57d8d3490b2fa99f278f1c37d87dad9b221acd575192ffae1784f8e60ec7cee4068b6b988f0433d96d6a1b1865f4e155e9fe020279f434f3bf1bd117b717b92f6cd1cc9bea7d45978bcc3f24bda631a36910110a6ec06da35f8966c9279d130347594f13e9e07514fa370754d1424c0a1545c5070ef9fb2acd14233e8a50bfc5978b5bdf8bc1714731f798d21e2004117c61f2989dd44f0cf027b27d4019e81ed4b5c31db347c4a3a4d85048d7093cf16753d7b0d15e078f5c7a5205dc2f87e330a1f716738dce1c6180e9d02869b5546f1c4d2748f8c90d9693cba4e0079297d22fd61402dea32ff0eb69ebd65a5d0b687d87e3a8b2c42b648aa723c7c7daf37abcc4bb85caea2ee8f55bec20e913b3324ab8f5c3304f820d42ad1b9f2ffc1a3af9927136b4419e1e579ab4c2ae3c776d293d397d575df181e6cae0a4ada5d67ecea171cca3288d57c7bbdaee3befe745fb7d634f70386d873b90c4d6c6596bb65af68f9e5121e67ebf0d89d3c909ceedfb32ce9575a7758ff080724e1ab5d5f43074ecb53a479af21ed03d7b6899c36631c0166f9d47e5e1d4528a5d3d3f744029c4b1c190cbfbad06f5f83f7ad0429fa9a2719c56ffe3783460e166de2d8>`

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

func NewRandomAmneziaConfig(version AmneziaVersion) (*AmneziaConfig, error) {
	if version == "" {
		version = AWG2
	}

	switch version {
	case AWG2, AWG3, AWG31:
	default:
		return nil, fmt.Errorf(
			"unsupported AmneziaWG version %q",
			version,
		)
	}

	cfg := &AmneziaConfig{
		Version: version,

		// Same base values as the known working configuration.
		Jc:   4,
		Jmin: 40,
		Jmax: 70,

		// Keep S1-S4 disabled for compatibility.
		S1: 0,
		S2: 0,
		S3: 0,
		S4: 0,

		// Compatibility values.
		H1: "1",
		H2: "2",
		H3: "3",
		H4: "4",

		// Known working CPS signature.
		I1: defaultI1,
	}

	switch version {
	case AWG2:
		// AWG2 uses only the basic obfuscation parameters.

	case AWG3:
		// Parameters based on the working AWG3 profile.
		cfg.ContentPaddingAddition = randomRange(34, 73)
		cfg.RekeyAfterTime = randomRange(64, 125)
		cfg.RekeyTimeout = randomRange(7, 13)
		cfg.RejectAfterTime = randomRange(68, 118)
		cfg.KeepaliveTimeout = randomRange(10, 17)
		cfg.MaxHandshakeAttempts = randomRange(5, 25)

	case AWG31:
		// Parameters based on the working AWG3.1 profile.
		cfg.ContentPaddingAddition = randomRange(34, 73)
		cfg.RekeyAfterTime = randomRange(64, 125)
		cfg.RekeyTimeout = randomRange(9, 13)
		cfg.RejectAfterTime = randomRange(86, 101)
		cfg.KeepaliveTimeout = randomRange(10, 13)
		cfg.MaxHandshakeAttempts = randomRange(7, 39)

		cfg.RandomTrailers = true
		cfg.DisableCookies = true
	}

	return cfg, nil
}

func LoadAmneziaConfig(path string) (*AmneziaConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf(
			"read AWG config %q: %w",
			path,
			err,
		)
	}

	var cfg AmneziaConfig

	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf(
			"parse AWG config %q: %w",
			path,
			err,
		)
	}

	if cfg.Version == "" {
		cfg.Version = AWG2
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf(
			"invalid AWG config %q: %w",
			path,
			err,
		)
	}

	return &cfg, nil
}

func (c *AmneziaConfig) Validate() error {
	if c == nil {
		return fmt.Errorf("AmneziaWG config is nil")
	}

	switch c.Version {
	case AWG2, AWG3, AWG31:
	default:
		return fmt.Errorf(
			"unsupported AmneziaWG version %q",
			c.Version,
		)
	}

	if c.Jc > 128 {
		return fmt.Errorf("Jc must be <= 128")
	}

	if c.Jmin > c.Jmax {
		return fmt.Errorf("Jmin must be <= Jmax")
	}

	if c.Jmax >= 1280 {
		return fmt.Errorf("Jmax must be below 1280")
	}

	if c.H1 == "" ||
		c.H2 == "" ||
		c.H3 == "" ||
		c.H4 == "" {
		return fmt.Errorf("H1-H4 must not be empty")
	}

	if c.Version == AWG2 {
		if c.ContentPaddingAddition != "" ||
			c.RekeyAfterTime != "" ||
			c.RekeyTimeout != "" ||
			c.RejectAfterTime != "" ||
			c.KeepaliveTimeout != "" ||
			c.MaxHandshakeAttempts != "" ||
			c.RandomTrailers ||
			c.DisableCookies ||
			c.HeaderProtectionKey != "" {
			return fmt.Errorf(
				"AWG2 config contains AWG3.x-only parameters",
			)
		}
	}

	if c.Version == AWG3 {
		if c.RandomTrailers || c.DisableCookies {
			return fmt.Errorf(
				"RandomTrailers and DisableCookies require AWG3.1",
			)
		}
	}

	if c.HeaderProtectionKey != "" {
		key, err := base64.StdEncoding.DecodeString(
			c.HeaderProtectionKey,
		)
		if err != nil {
			return fmt.Errorf(
				"invalid HeaderProtectionKey: %w",
				err,
			)
		}

		if len(key) != 32 {
			return fmt.Errorf(
				"HeaderProtectionKey must decode to exactly 32 bytes",
			)
		}

		if c.S1 < 12 ||
			c.S2 < 12 ||
			c.S3 < 12 ||
			c.S4 < 12 {
			return fmt.Errorf(
				"S1-S4 must all be >= 12 when HeaderProtectionKey is set",
			)
		}
	}

	return nil
}

func randomRange(min, max uint16) string {
	return fmt.Sprintf("%d-%d", min, max)
}

func randomUint16(min, max uint16) (uint16, error) {
	if min > max {
		return 0, fmt.Errorf(
			"invalid random range %d-%d",
			min,
			max,
		)
	}

	var b [2]byte

	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}

	v := uint32(b[0])<<8 | uint32(b[1])

	return uint16(
		uint32(min) + v%(uint32(max)-uint32(min)+1),
	), nil
}

func RandomHeaderProtectionKey() (string, error) {
	key := make([]byte, 32)

	if _, err := rand.Read(key); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(key), nil
}

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
