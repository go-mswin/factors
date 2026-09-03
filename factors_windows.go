// Copyright (c) the go-mswin authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package factors

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	authn "github.com/go-authn/fido"
	"github.com/go-authn/mfa"
	"github.com/go-mswin/webauthn"
	"github.com/go-mswin/winrt"
)

// platformAskHello asks Windows Hello and reads the answer unreduced.
//
// It uses winrt.Verify rather than winrt.RequireUserConsent because the latter
// folds every outcome into a boolean, and this is exactly the caller that must
// not lose the difference: a machine with no verifier, no enrolment, or a
// policy against it has refused nobody, and telling somebody they failed sends
// them to try harder at something that does not exist.
func platformAskHello(ctx context.Context, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	res, err := winrt.Verify(reason)
	if err != nil {
		return err
	}
	switch {
	case res == winrt.UserConsentVerified:
		return nil
	case !res.Asked():
		// DeviceNotPresent, NotConfiguredForUser, DisabledByPolicy, DeviceBusy.
		return unavailable(fmt.Errorf("Windows Hello: %v", res))
	default:
		// Canceled, RetriesExhausted: somebody was there and answered.
		return fmt.Errorf("factors: Windows Hello: %v", res)
	}
}

// platformAskKey asks a security key for an assertion, through Windows.
//
// The challenge is random. Nothing here verifies the signature, so there is no
// protocol to bind one to -- and a FIXED challenge would let a recorded
// assertion be replayed at this function for ever. A caller who needs a
// VERIFIABLE assertion should use go-mswin/webauthn directly and check it.
func platformAskKey(ctx context.Context, f keyFactor) error {
	var challenge [sha256.Size]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return fmt.Errorf("factors: cannot make a challenge: %w", err)
	}
	req := webauthn.Request{
		RPID:      f.rpID,
		Origin:    f.origin,
		Challenge: challenge[:],
		// ⛔ This is what earns the possession claim. Without it Windows may
		// answer with the machine itself, and "something you have" would mean
		// the computer already in front of the person.
		Attachment:   webauthn.CrossPlatform,
		Verification: webauthn.VerificationDiscouraged,
	}
	if f.verify {
		req.Verification = webauthn.VerificationRequired
	}
	if len(f.credential) > 0 {
		req.Allow = []webauthn.Credential{{ID: f.credential}}
	}

	a, err := webauthn.Assert(ctx, req)
	if err != nil {
		var werr *webauthn.Error
		if errors.Is(err, webauthn.ErrUnsupported) {
			return unavailable(err)
		}
		if errors.As(err, &werr) && werr.Unavailable() {
			return unavailable(err)
		}
		return err
	}

	// Windows answering is not enough: the authenticator must say a person was
	// there, and -- when asked to -- that it established who.
	ad, err := authn.ParseAuthData(a.AuthenticatorData)
	if err != nil {
		return fmt.Errorf("factors: %s answered with authenticator data this cannot read: %w", f.Name(), err)
	}
	if !ad.Flags.Has(authn.FlagUP) {
		return fmt.Errorf("factors: %s answered without anyone touching it", f.Name())
	}
	if f.verify && !ad.Flags.Has(authn.FlagUV) {
		return fmt.Errorf("factors: %s was asked to establish who holds it and did not", f.Name())
	}

	// The constraint was a REQUEST; this is an observation, and they can
	// differ. When Windows says what answered and it says the machine itself,
	// the possession claim is false and saying so is the whole point of
	// reading it back. Silence is not a contradiction: an older Windows
	// reports no transport at all.
	if carried, known := a.Transport.Carried(); known && !carried {
		return fmt.Errorf("factors: asked for %s and %s answered, which is not something carried",
			f.Name(), a.Transport)
	}
	return nil
}

// compile-time proof that the factors satisfy the interface.
var (
	_ mfa.Factor = helloFactor{}
	_ mfa.Factor = keyFactor{}
)
