package wireguard

import (
	"strings"
	"testing"
)

func TestGenerateProfileAWG(t *testing.T) {
	result, err := generateProfile(&ProfileData{
		PrivateKey: "1",
		Address1:   "2",
		Address2:   "3",
		PublicKey:  "4",
		Endpoint:   "5",
		Amnezia: &AmneziaConfig{
			Version: AWG2,
			Jc: 4, Jmin: 40, Jmax: 70,
			S1: 0, S2: 0, S3: 0, S4: 0,
			H1: "1", H2: "2", H3: "3", H4: "4",
			I1: "<r 32>",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"Jc = 4",
		"Jmin = 40",
		"Jmax = 70",
		"S1 = 0",
		"H1 = 1",
		"I1 = <r 32>",
		"Endpoint = 5",
	} {
		if !strings.Contains(result, want) {
			t.Fatalf("generated profile does not contain %q:\n%s", want, result)
		}
	}
}

func TestGenerateProfileWithoutAWG(t *testing.T) {
	result, err := generateProfile(&ProfileData{
		PrivateKey: "1", Address1: "2", Address2: "3",
		PublicKey: "4", Endpoint: "5",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result, "Jc =") {
		t.Fatal("plain profile unexpectedly contains AWG settings")
	}
}
