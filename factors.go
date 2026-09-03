// Copyright (c) the go-mswin authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package factors makes Windows's authentication factors usable by
// github.com/go-authn/mfa.
//
// Its two factors come from two different packages, which is the whole shape
// of Windows: [go-mswin/winrt] asks Windows Hello, and [go-mswin/webauthn]
// asks a security key through webauthn.dll. Neither binding knows what a
// policy is, and neither should — a program that only wants a Hello prompt
// must not end up importing one.
//
//	r, err := mfa.Verify(ctx, mfa.Policy{Count: 2},
//	    factors.WindowsHello("unlock the vault"),
//	    factors.SecurityKey("example.test", credentialID),
//	)
//
// # ⛔ Windows cannot offer an inherence factor
//
// This is the finding that shapes the package, and it is worth stating plainly
// rather than papering over.
//
// Windows Hello accepts a face, a fingerprint, or a **PIN**, and the person
// chooses. Nothing in UserConsentVerifier or in a WebAuthn assertion reports
// WHICH — the assertion's "user verified" bit is set the same way for all
// three. A PIN is something known; a face is something one is. So a factor
// that claimed [mfa.Inherence] here would be claiming to know something
// Windows never said.
//
// [WindowsHello] therefore reports [mfa.Unknown], and a policy asking for
// distinct KINDS will never count it towards them. That is not a limitation of
// this package working around an API; it is the API declining to say, reported
// faithfully. macOS can do better — LocalAuthentication has a biometrics-only
// policy, so github.com/go-macos/factors offers a real inherence factor — and
// the difference between the two platforms is real, not an oversight here.
//
// The consequence is worth knowing before designing around it:
// mfa.Policy{Count: 2, DistinctKinds: true} cannot be satisfied on Windows by
// these two factors alone. A caller who needs two kinds must supply the
// knowledge factor themselves, and then it is theirs to be honest about.
package factors

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-authn/mfa"
)

// helloFactor asks Windows Hello.
type helloFactor struct {
	reason string
}

// WindowsHello is the authenticator built into this machine, as a factor.
//
// reason is what Windows shows the person in its own prompt, so it should say
// what is being unlocked.
//
// Its kind is [mfa.Unknown], honestly: see the package documentation. What it
// proves is that somebody satisfied this machine's own check, which is worth
// having — it is simply not a KIND that can be shown to differ from a
// passphrase.
func WindowsHello(reason string) mfa.Factor { return helloFactor{reason: reason} }

func (f helloFactor) Name() string { return "Windows Hello" }

// Kind is deliberately unclassified. Hello may have been a face, a
// fingerprint, or a PIN, and Windows does not say which.
func (f helloFactor) Kind() mfa.Kind { return mfa.Unknown }

// keyFactor asks a security key, through Windows.
type keyFactor struct {
	rpID       string
	origin     string
	credential []byte
	// verify demands that the authenticator establish WHO is holding the key
	// -- its PIN or its own sensor -- not merely that somebody touched it.
	verify bool
}

// SecurityKey is a registered credential on a carried authenticator.
//
// The request is constrained to a cross-platform authenticator, so Windows
// Hello cannot answer it. That constraint is what makes [mfa.Possession] a
// true statement: without it, Windows would be free to satisfy the request
// with the machine itself, and "something you have" would mean the computer
// already in front of the person.
//
// credentialID is what a registration returned. Registering is not done here;
// see go-mswin/webauthn.
func SecurityKey(rpID string, credentialID []byte) mfa.Factor {
	return keyFactor{rpID: rpID, origin: "https://" + rpID, credential: credentialID}
}

// VerifiedSecurityKey is the same, with the key asked to establish who holds
// it.
//
// The kind does not change. Whatever the key asked for -- its own PIN, its own
// fingerprint reader -- never reaches this machine and identifies nobody to
// us; it protects the key. Counting it as a second factor would let one object
// masquerade as two.
func VerifiedSecurityKey(rpID string, credentialID []byte) mfa.Factor {
	f := SecurityKey(rpID, credentialID).(keyFactor)
	f.verify = true
	return f
}

// WithOrigin overrides the origin sent in the client data.
//
// It defaults to "https://" + rpID, which is what a program that is not a web
// page wants. A browser-like caller with a real page has a real origin and
// should say so, because Windows checks that the two agree.
func WithOrigin(f mfa.Factor, origin string) mfa.Factor {
	k, ok := f.(keyFactor)
	if !ok {
		return f
	}
	k.origin = origin
	return k
}

func (f keyFactor) Name() string {
	if f.verify {
		return "your security key and its PIN"
	}
	return "your security key"
}

// Kind is possession, and the cross-platform constraint is what earns it.
func (f keyFactor) Kind() mfa.Kind { return mfa.Possession }

// unavailable wraps err as something a policy treats as "not asked".
func unavailable(err error) error {
	return fmt.Errorf("%w: %w", mfa.ErrUnavailable, err)
}

// The seams both factors go through, so a test can drive a machine with no
// Hello, a person who cancels, an empty USB port and a key that answers
// without anyone touching it -- on a machine where none of those happen.
var (
	askHello = platformAskHello
	askKey   = platformAskKey
)

// Verify asks Windows Hello.
func (f helloFactor) Verify(ctx context.Context) error {
	if f.reason == "" {
		// Windows shows this to the person. Failing here rather than there
		// means the error names the programming mistake instead of quoting a
		// runtime complaint about it.
		return errors.New("factors: a Windows Hello prompt needs a reason to show the person")
	}
	return askHello(ctx, f.reason)
}

// Verify asks the security key.
func (f keyFactor) Verify(ctx context.Context) error {
	if f.rpID == "" {
		return errors.New("factors: a security key needs a relying party id to assert for")
	}
	if f.origin == "" {
		return errors.New("factors: a security key needs an origin")
	}
	return askKey(ctx, f)
}
