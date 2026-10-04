// Copyright (c) the go-mswin authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package factors

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

var testPriv = func() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}()

// testKey stands for a registered credential's public key.
var testKey = &testPriv.PublicKey

// answer is an assertion a genuine authenticator would return for f.
type answer struct {
	authData, clientData, sig, credID []byte
}

func genuine(t *testing.T, f keyFactor, challenge []byte, flags byte) answer {
	t.Helper()
	h := sha256.Sum256([]byte(f.rpID))
	ad := append(append([]byte{}, h[:]...), flags, 0, 0, 0, 7)
	cd, err := json.Marshal(map[string]any{"type": "webauthn.get",
		"challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": f.origin})
	if err != nil {
		t.Fatal(err)
	}
	return signed(t, ad, cd, f.credential)
}

func signed(t *testing.T, ad, cd, credID []byte) answer {
	t.Helper()
	cdh := sha256.Sum256(cd)
	d := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, testPriv, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return answer{ad, cd, sig, credID}
}

// ⛔ The assertion is VERIFIED against the credential's public key. Before,
// only the flags the authenticator reported were read, so any device that
// answered passed as the key -- a forged answer below is exactly what a
// programmable USB board would send.
func TestAnAssertionIsVerifiedAgainstTheRegisteredCredential(t *testing.T) {
	f := SecurityKey("example.test", []byte("cred"), testKey).(keyFactor)
	v := VerifiedSecurityKey("example.test", []byte("cred"), testKey).(keyFactor)
	ch := []byte("a fresh challenge")
	const up, uv = 0x01, 0x04

	ok := genuine(t, f, ch, up)
	if err := checkAssertion(f, ch, ok.authData, ok.clientData, ok.sig, ok.credID); err != nil {
		t.Fatalf("a genuine assertion was refused: %v", err)
	}
	okv := genuine(t, v, ch, up|uv)
	if err := checkAssertion(v, ch, okv.authData, okv.clientData, okv.sig, okv.credID); err != nil {
		t.Fatalf("a genuine verified assertion was refused: %v", err)
	}

	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherRP := SecurityKey("evil.test", []byte("cred"), testKey).(keyFactor)
	otherRP.origin = f.origin
	cases := []struct {
		name string
		f    keyFactor
		a    answer
		want string
	}{
		{"client data that is not JSON", f, signed(t, ok.authData, []byte("{"), ok.credID), "not JSON"},
		{"another challenge", f, genuine(t, f, []byte("an old one"), up), "another request"},
		{"another origin", f, func() answer { g := f; g.origin = "https://evil.test"; return genuine(t, g, ch, up) }(), "another request"},
		{"a registration, not an assertion", f, func() answer {
			cd, _ := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": base64.RawURLEncoding.EncodeToString(ch), "origin": f.origin})
			return signed(t, ok.authData, cd, ok.credID)
		}(), "another request"},
		{"a signature the credential did not make", f, answer{ok.authData, ok.clientData, []byte{0x30, 0}, ok.credID}, "did not make"},
		{"a signature by another key", f, func() answer {
			cdh := sha256.Sum256(ok.clientData)
			d := sha256.Sum256(append(append([]byte{}, ok.authData...), cdh[:]...))
			sig, _ := ecdsa.SignASN1(rand.Reader, other, d[:])
			return answer{ok.authData, ok.clientData, sig, ok.credID}
		}(), "did not make"},
		{"authenticator data too short to read", f, signed(t, ok.authData[:10], ok.clientData, ok.credID), "cannot read"},
		{"another relying party", f, genuine(t, otherRP, ch, up), "another relying party"},
		{"another credential", f, func() answer { a := genuine(t, f, ch, up); a.credID = []byte("other"); return a }(), "another credential"},
		{"nobody touched it", f, genuine(t, f, ch, 0), "without anyone touching"},
		{"not verified when asked to be", v, genuine(t, v, ch, up), "establish who"},
	}
	for _, c := range cases {
		err := checkAssertion(c.f, ch, c.a.authData, c.a.clientData, c.a.sig, c.a.credID)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error mentioning %q", c.name, err, c.want)
		}
	}
}

// A factor without the credential's public key refuses before anything is
// asked: nothing could check what the key signs.
func TestASecurityKeyWithoutItsPublicKeyIsRefused(t *testing.T) {
	for _, pub := range []*ecdsa.PublicKey{nil, func() *ecdsa.PublicKey {
		k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		return &k.PublicKey
	}()} {
		err := SecurityKey("example.test", nil, pub).Verify(context.Background())
		if err == nil || !strings.Contains(err.Error(), "public key") {
			t.Errorf("a factor with public key %v gave %v", pub, err)
		}
	}
}
