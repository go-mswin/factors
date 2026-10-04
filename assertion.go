// Copyright (c) the go-mswin authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package factors

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	authn "github.com/go-authn/fido"
)

// checkAssertion verifies an assertion as a relying party would (WebAuthn
// §7.2), for the request f made with challenge.
//
// It is portable so that every platform's tests reach it; only Windows calls
// it. The order puts the signature before anything the authenticator merely
// SAYS: flags in unsigned bytes prove nothing.
func checkAssertion(f keyFactor, challenge, authData, clientDataJSON, signature, credentialID []byte) error {
	var cd struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(clientDataJSON, &cd); err != nil {
		return fmt.Errorf("factors: %s answered with client data that is not JSON: %w", f.Name(), err)
	}
	if cd.Type != "webauthn.get" || cd.Challenge != base64.RawURLEncoding.EncodeToString(challenge) || cd.Origin != f.origin {
		return fmt.Errorf("factors: %s answered for another request", f.Name())
	}
	cdHash := sha256.Sum256(clientDataJSON)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdHash[:]...))
	if !ecdsa.VerifyASN1(f.publicKey, digest[:], signature) {
		return fmt.Errorf("factors: %s answered with a signature its credential did not make", f.Name())
	}
	ad, err := authn.ParseAuthData(authData)
	if err != nil {
		return fmt.Errorf("factors: %s answered with authenticator data this cannot read: %w", f.Name(), err)
	}
	if ad.RPIDHash != sha256.Sum256([]byte(f.rpID)) {
		return fmt.Errorf("factors: %s answered for another relying party", f.Name())
	}
	if len(f.credential) > 0 && len(credentialID) > 0 && !bytes.Equal(credentialID, f.credential) {
		return fmt.Errorf("factors: %s answered with another credential", f.Name())
	}
	if !ad.Flags.Has(authn.FlagUP) {
		return fmt.Errorf("factors: %s answered without anyone touching it", f.Name())
	}
	if f.verify && !ad.Flags.Has(authn.FlagUV) {
		return fmt.Errorf("factors: %s was asked to establish who holds it and did not", f.Name())
	}
	return nil
}
