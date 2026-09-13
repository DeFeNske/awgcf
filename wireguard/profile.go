package wireguard

import (
	"bytes"
	"io/ioutil"
	"text/template"

	"github.com/cockroachdb/errors"
)

var profileTemplate = `[Interface]
PrivateKey = {{ .PrivateKey }}
Address = {{ .Address1 }}/32, {{ .Address2 }}/128
DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
MTU = 1280
{{- if .Amnezia }}
Jc = {{ .Amnezia.Jc }}
Jmin = {{ .Amnezia.Jmin }}
Jmax = {{ .Amnezia.Jmax }}
S1 = {{ .Amnezia.S1 }}
S2 = {{ .Amnezia.S2 }}
S3 = {{ .Amnezia.S3 }}
S4 = {{ .Amnezia.S4 }}
H1 = {{ .Amnezia.H1 }}
H2 = {{ .Amnezia.H2 }}
H3 = {{ .Amnezia.H3 }}
H4 = {{ .Amnezia.H4 }}
{{- if .Amnezia.I1 }}
I1 = {{ .Amnezia.I1 }}
{{- end }}
{{- if .Amnezia.I2 }}
I2 = {{ .Amnezia.I2 }}
{{- end }}
{{- if .Amnezia.I3 }}
I3 = {{ .Amnezia.I3 }}
{{- end }}
{{- if .Amnezia.I4 }}
I4 = {{ .Amnezia.I4 }}
{{- end }}
{{- if .Amnezia.I5 }}
I5 = {{ .Amnezia.I5 }}
{{- end }}
{{- if .Amnezia.HeaderProtectionKey }}
HeaderProtectionKey = {{ .Amnezia.HeaderProtectionKey }}
{{- end }}
{{- if .Amnezia.ContentPaddingAddition }}
ContentPaddingAddition = {{ .Amnezia.ContentPaddingAddition }}
{{- end }}
{{- if .Amnezia.RekeyAfterTime }}
RekeyAfterTime = {{ .Amnezia.RekeyAfterTime }}
{{- end }}
{{- if .Amnezia.RekeyTimeout }}
RekeyTimeout = {{ .Amnezia.RekeyTimeout }}
{{- end }}
{{- if .Amnezia.RejectAfterTime }}
RejectAfterTime = {{ .Amnezia.RejectAfterTime }}
{{- end }}
{{- if .Amnezia.KeepaliveTimeout }}
KeepaliveTimeout = {{ .Amnezia.KeepaliveTimeout }}
{{- end }}
{{- if .Amnezia.MaxHandshakeAttempts }}
MaxHandshakeAttempts = {{ .Amnezia.MaxHandshakeAttempts }}
{{- end }}
{{- if .Amnezia.RandomTrailers }}
RandomTrailers = on
{{- end }}
{{- if .Amnezia.DisableCookies }}
DisableCookies = on
{{- end }}
{{- end }}
[Peer]
PublicKey = {{ .PublicKey }}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {{ .Endpoint }}
`

type Profile struct {
	profileString string
}

type ProfileData struct {
	PrivateKey string
	Address1   string
	Address2   string
	PublicKey  string
	Endpoint   string
	Amnezia    *AmneziaConfig
}

func NewProfile(data *ProfileData) (*Profile, error) {
	profileString, err := generateProfile(data)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &Profile{profileString: profileString}, nil
}

func generateProfile(data *ProfileData) (string, error) {
	t, err := template.New("").Parse(profileTemplate)
	if err != nil {
		return "", errors.WithStack(err)
	}
	var result bytes.Buffer
	if err := t.Execute(&result, data); err != nil {
		return "", errors.WithStack(err)
	}
	return result.String(), nil
}

func (p *Profile) Save(profileFile string) error {
	return ioutil.WriteFile(profileFile, []byte(p.profileString), 0600)
}
