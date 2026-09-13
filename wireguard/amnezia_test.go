package wireguard

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewRandomAmneziaConfigAWG2(t *testing.T) {
	cfg, err := NewRandomAmneziaConfig(AWG2)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Version != AWG2 {
		t.Fatalf("version = %q, want %q", cfg.Version, AWG2)
	}

	if cfg.Jc != 4 {
		t.Fatalf("Jc = %d, want 4", cfg.Jc)
	}

	if cfg.Jmin != 40 {
		t.Fatalf("Jmin = %d, want 40", cfg.Jmin)
	}

	if cfg.Jmax != 70 {
		t.Fatalf("Jmax = %d, want 70", cfg.Jmax)
	}

	if cfg.S1 != 0 || cfg.S2 != 0 ||
		cfg.S3 != 0 || cfg.S4 != 0 {
		t.Fatalf(
			"S1-S4 = %d,%d,%d,%d, want 0,0,0,0",
			cfg.S1,
			cfg.S2,
			cfg.S3,
			cfg.S4,
		)
	}

	if cfg.H1 != "1" ||
		cfg.H2 != "2" ||
		cfg.H3 != "3" ||
		cfg.H4 != "4" {
		t.Fatalf(
			"H1-H4 = %q,%q,%q,%q, want 1,2,3,4",
			cfg.H1,
			cfg.H2,
			cfg.H3,
			cfg.H4,
		)
	}

	if cfg.I1 == "" {
		t.Fatal("I1 must not be empty")
	}

	if !strings.HasPrefix(cfg.I1, "<b 0x") {
		t.Fatalf("unexpected I1 format: %q", cfg.I1)
	}

	if cfg.ContentPaddingAddition != "" {
		t.Fatal("AWG2 must not contain ContentPaddingAddition")
	}

	if cfg.RekeyAfterTime != "" {
		t.Fatal("AWG2 must not contain RekeyAfterTime")
	}

	if cfg.RekeyTimeout != "" {
		t.Fatal("AWG2 must not contain RekeyTimeout")
	}

	if cfg.RejectAfterTime != "" {
		t.Fatal("AWG2 must not contain RejectAfterTime")
	}

	if cfg.KeepaliveTimeout != "" {
		t.Fatal("AWG2 must not contain KeepaliveTimeout")
	}

	if cfg.MaxHandshakeAttempts != "" {
		t.Fatal("AWG2 must not contain MaxHandshakeAttempts")
	}

	if cfg.RandomTrailers {
		t.Fatal("AWG2 must not enable RandomTrailers")
	}

	if cfg.DisableCookies {
		t.Fatal("AWG2 must not enable DisableCookies")
	}

	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestNewRandomAmneziaConfigAWG3(t *testing.T) {
	cfg, err := NewRandomAmneziaConfig(AWG3)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Version != AWG3 {
		t.Fatalf("version = %q, want %q", cfg.Version, AWG3)
	}

	if cfg.Jc != 4 {
		t.Fatalf("Jc = %d, want 4", cfg.Jc)
	}

	if cfg.Jmin != 40 {
		t.Fatalf("Jmin = %d, want 40", cfg.Jmin)
	}

	if cfg.Jmax != 70 {
		t.Fatalf("Jmax = %d, want 70", cfg.Jmax)
	}

	if cfg.I1 == "" {
		t.Fatal("I1 must not be empty")
	}

	if cfg.ContentPaddingAddition == "" {
		t.Fatal("AWG3 must contain ContentPaddingAddition")
	}

	if cfg.RekeyAfterTime == "" {
		t.Fatal("AWG3 must contain RekeyAfterTime")
	}

	if cfg.RekeyTimeout == "" {
		t.Fatal("AWG3 must contain RekeyTimeout")
	}

	if cfg.RejectAfterTime == "" {
		t.Fatal("AWG3 must contain RejectAfterTime")
	}

	if cfg.KeepaliveTimeout == "" {
		t.Fatal("AWG3 must contain KeepaliveTimeout")
	}

	if cfg.MaxHandshakeAttempts == "" {
		t.Fatal("AWG3 must contain MaxHandshakeAttempts")
	}

	if cfg.RandomTrailers {
		t.Fatal("AWG3 must not enable RandomTrailers")
	}

	if cfg.DisableCookies {
		t.Fatal("AWG3 must not enable DisableCookies")
	}

	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestNewRandomAmneziaConfigAWG31(t *testing.T) {
	cfg, err := NewRandomAmneziaConfig(AWG31)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Version != AWG31 {
		t.Fatalf("version = %q, want %q", cfg.Version, AWG31)
	}

	if cfg.Jc != 4 {
		t.Fatalf("Jc = %d, want 4", cfg.Jc)
	}

	if cfg.Jmin != 40 {
		t.Fatalf("Jmin = %d, want 40", cfg.Jmin)
	}

	if cfg.Jmax != 70 {
		t.Fatalf("Jmax = %d, want 70", cfg.Jmax)
	}

	if cfg.I1 == "" {
		t.Fatal("I1 must not be empty")
	}

	if cfg.ContentPaddingAddition == "" {
		t.Fatal("AWG3.1 must contain ContentPaddingAddition")
	}

	if cfg.RekeyAfterTime == "" {
		t.Fatal("AWG3.1 must contain RekeyAfterTime")
	}

	if cfg.RekeyTimeout == "" {
		t.Fatal("AWG3.1 must contain RekeyTimeout")
	}

	if cfg.RejectAfterTime == "" {
		t.Fatal("AWG3.1 must contain RejectAfterTime")
	}

	if cfg.KeepaliveTimeout == "" {
		t.Fatal("AWG3.1 must contain KeepaliveTimeout")
	}

	if cfg.MaxHandshakeAttempts == "" {
		t.Fatal("AWG3.1 must contain MaxHandshakeAttempts")
	}

	if !cfg.RandomTrailers {
		t.Fatal("AWG3.1 must enable RandomTrailers")
	}

	if !cfg.DisableCookies {
		t.Fatal("AWG3.1 must enable DisableCookies")
	}

	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestNewRandomAmneziaConfigRejectsUnknownVersion(t *testing.T) {
	_, err := NewRandomAmneziaConfig("awg4")

	if err == nil {
		t.Fatal("expected error for unsupported version")
	}

	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAWG2RejectsAWG3Parameters(t *testing.T) {
	cfg := &AmneziaConfig{
		Version: AWG2,

		Jc:   4,
		Jmin: 40,
		Jmax: 70,

		S1: 0,
		S2: 0,
		S3: 0,
		S4: 0,

		H1: "1",
		H2: "2",
		H3: "3",
		H4: "4",

		ContentPaddingAddition: "34-73",
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateAWG3RejectsAWG31Flags(t *testing.T) {
	cfg := &AmneziaConfig{
		Version: AWG3,

		Jc:   4,
		Jmin: 40,
		Jmax: 70,

		S1: 0,
		S2: 0,
		S3: 0,
		S4: 0,

		H1: "1",
		H2: "2",
		H3: "3",
		H4: "4",

		ContentPaddingAddition: "34-73",
		RekeyAfterTime:         "64-125",
		RekeyTimeout:           "7-13",
		RejectAfterTime:        "68-118",
		KeepaliveTimeout:       "10-17",
		MaxHandshakeAttempts:   "5-25",

		RandomTrailers: true,
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateHeaderProtection(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(
		make([]byte, 32),
	)

	cfg := &AmneziaConfig{
		Version: AWG31,

		Jc:   4,
		Jmin: 40,
		Jmax: 70,

		S1: 12,
		S2: 12,
		S3: 12,
		S4: 12,

		H1: "1",
		H2: "2",
		H3: "3",
		H4: "4",

		HeaderProtectionKey:    key,
		ContentPaddingAddition: "34-73",
		RekeyAfterTime:         "64-125",
		RekeyTimeout:           "9-13",
		RejectAfterTime:        "86-101",
		KeepaliveTimeout:       "10-13",
		MaxHandshakeAttempts:   "7-39",

		RandomTrailers: true,
		DisableCookies: true,
	}

	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsInvalidHeaderProtectionKey(t *testing.T) {
	cfg := &AmneziaConfig{
		Version: AWG31,

		Jc:   4,
		Jmin: 40,
		Jmax: 70,

		S1: 12,
		S2: 12,
		S3: 12,
		S4: 12,

		H1: "1",
		H2: "2",
		H3: "3",
		H4: "4",

		HeaderProtectionKey: "invalid",
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateRejectsShortHeaderProtectionKey(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(
		make([]byte, 16),
	)

	cfg := &AmneziaConfig{
		Version: AWG31,

		Jc:   4,
		Jmin: 40,
		Jmax: 70,

		S1: 12,
		S2: 12,
		S3: 12,
		S4: 12,

		H1: "1",
		H2: "2",
		H3: "3",
		H4: "4",

		HeaderProtectionKey: key,
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateRejectsShortHeaderProtectionPrefix(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(
		make([]byte, 32),
	)

	cfg := &AmneziaConfig{
		Version: AWG31,

		Jc:   4,
		Jmin: 40,
		Jmax: 70,

		S1: 11,
		S2: 12,
		S3: 12,
		S4: 12,

		H1: "1",
		H2: "2",
		H3: "3",
		H4: "4",

		HeaderProtectionKey: key,
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadAmneziaConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "awg.json")

	data := []byte(`{
		"version": "awg3.1",
		"jc": 4,
		"jmin": 40,
		"jmax": 70,
		"s1": 0,
		"s2": 0,
		"s3": 0,
		"s4": 0,
		"h1": "1",
		"h2": "2",
		"h3": "3",
		"h4": "4",
		"i1": "<b 0xce00>",
		"content_padding_addition": "34-73",
		"rekey_after_time": "64-125",
		"rekey_timeout": "9-13",
		"reject_after_time": "86-101",
		"keepalive_timeout": "10-13",
		"max_handshake_attempts": "7-39",
		"random_trailers": true,
		"disable_cookies": true
	}`)

	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadAmneziaConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Version != AWG31 {
		t.Fatalf(
			"version = %q, want %q",
			cfg.Version,
			AWG31,
		)
	}

	if cfg.ContentPaddingAddition != "34-73" {
		t.Fatalf(
			"ContentPaddingAddition = %q, want %q",
			cfg.ContentPaddingAddition,
			"34-73",
		)
	}

	if !cfg.RandomTrailers {
		t.Fatal("RandomTrailers must be enabled")
	}

	if !cfg.DisableCookies {
		t.Fatal("DisableCookies must be enabled")
	}
}
