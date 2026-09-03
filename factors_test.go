// Copyright (c) the go-mswin authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package factors

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-authn/mfa"
)

// swap installs fake platform answers and puts the real ones back.
func swap(t *testing.T, hello func(context.Context, string) error, key func(context.Context, keyFactor) error) {
	t.Helper()
	oh, ok := askHello, askKey
	t.Cleanup(func() { askHello, askKey = oh, ok })
	if hello != nil {
		askHello = hello
	}
	if key != nil {
		askKey = key
	}
}

// TestWindowsCannotOfferAnInherenceFactor is the finding that shapes this
// package, held as a test so nobody quietly "fixes" it.
//
// Windows Hello accepts a face, a fingerprint or a PIN, and nothing reports
// which. A factor claiming inherence here would be claiming to know something
// Windows never said -- so a two-KIND policy cannot be satisfied by these two
// factors, and that is the honest answer rather than a bug.
func TestWindowsCannotOfferAnInherenceFactor(t *testing.T) {
	hello := WindowsHello("unlock the vault")
	key := SecurityKey("example.test", []byte("cred"))

	if hello.Kind() != mfa.Unknown {
		t.Errorf("Windows Hello claims %v; Windows never says which modality was used", hello.Kind())
	}
	if key.Kind() != mfa.Possession {
		t.Errorf("a security key is %v, want possession", key.Kind())
	}

	swap(t, func(context.Context, string) error { return nil },
		func(context.Context, keyFactor) error { return nil })

	// A plain count of two is satisfied: two things really did answer.
	if _, err := mfa.Verify(context.Background(), mfa.Policy{Count: 2}, hello, key); err != nil {
		t.Errorf("a plain count of two refused two answers: %v", err)
	}
	// Two KINDS is not, and must not be.
	if _, err := mfa.Verify(context.Background(),
		mfa.Policy{Count: 2, DistinctKinds: true}, hello, key); err == nil {
		t.Fatal("a two-KIND policy was satisfied by an unclassified factor")
	}
}

// TestAPINOnTheKeyIsNotASecondFactor. Whatever the key asked for never reaches
// this machine and identifies nobody to us; it protects the key.
func TestAPINOnTheKeyIsNotASecondFactor(t *testing.T) {
	if got := VerifiedSecurityKey("example.test", []byte("c")).Kind(); got != mfa.Possession {
		t.Errorf("a verified key is %v, want possession", got)
	}
	if !strings.Contains(VerifiedSecurityKey("e.test", nil).Name(), "PIN") {
		t.Error("the verified factor does not say what it will ask for")
	}
}

// TestNothingHereToAskIsNotAFailure. A machine with no Hello and an empty USB
// port have refused nobody.
func TestNothingHereToAskIsNotAFailure(t *testing.T) {
	swap(t,
		func(context.Context, string) error { return unavailable(errors.New("no verifier device")) },
		func(context.Context, keyFactor) error { return unavailable(errors.New("no key")) })

	r, err := mfa.Verify(context.Background(), mfa.Policy{Count: 1},
		WindowsHello("unlock"), SecurityKey("example.test", nil))
	if err == nil {
		t.Fatal("a machine with neither factor satisfied a policy")
	}
	for _, a := range r.Answers {
		if !a.Unavailable() {
			t.Errorf("%s was reported as a refusal rather than as absent", a.Name)
		}
	}
	// And an absent factor never ends an attempt, even with StopOnFirstFailure.
	swap(t, nil, func(context.Context, keyFactor) error { return nil })
	if _, err := mfa.Verify(context.Background(),
		mfa.Policy{Count: 1, StopOnFirstFailure: true},
		WindowsHello("unlock"), SecurityKey("example.test", nil)); err != nil {
		t.Errorf("an absent Hello ended the attempt: %v", err)
	}
}

func TestARefusalIsARefusal(t *testing.T) {
	swap(t, func(context.Context, string) error { return errors.New("Windows Hello: Canceled") },
		func(context.Context, keyFactor) error { return errors.New("nobody touched it") })
	r, err := mfa.Verify(context.Background(), mfa.Policy{Count: 1},
		WindowsHello("unlock"), SecurityKey("example.test", nil))
	if err == nil {
		t.Fatal("two refusals satisfied a policy")
	}
	for _, a := range r.Answers {
		if a.Unavailable() {
			t.Errorf("%s was reported as absent rather than as refusing", a.Name)
		}
	}
	if !strings.Contains(err.Error(), "Canceled") {
		t.Errorf("the error says %q, which does not name what happened", err)
	}
}

func TestAFactorRefusesAnIncompleteRequest(t *testing.T) {
	asked := 0
	swap(t, func(context.Context, string) error { asked++; return nil },
		func(context.Context, keyFactor) error { asked++; return nil })

	for _, c := range []struct {
		name string
		f    mfa.Factor
		want string
	}{
		{"a prompt with no reason", WindowsHello(""), "needs a reason"},
		{"a key with no relying party", SecurityKey("", nil), "relying party id"},
		{"a key with no origin", WithOrigin(SecurityKey("e.test", nil), ""), "needs an origin"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.f.Verify(context.Background())
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error says %q, which does not mention %q", err, c.want)
			}
		})
	}
	if asked != 0 {
		t.Errorf("the platform was asked %d time(s) for an incomplete request", asked)
	}
}

// TestTheOriginDefaultsToTheRelyingParty, because a program that is not a web
// page has no other sensible one, and Windows rejects a mismatch with a
// parameter error that names no parameter.
func TestTheOriginDefaultsToTheRelyingParty(t *testing.T) {
	var seen keyFactor
	swap(t, nil, func(_ context.Context, f keyFactor) error { seen = f; return nil })

	if err := SecurityKey("example.test", nil).Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if seen.origin != "https://example.test" {
		t.Errorf("origin defaulted to %q", seen.origin)
	}
	if err := WithOrigin(SecurityKey("example.test", nil), "https://login.example.test").
		Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if seen.origin != "https://login.example.test" {
		t.Errorf("WithOrigin gave %q", seen.origin)
	}
	// WithOrigin on something that is not a key factor changes nothing rather
	// than panicking: it is a helper, not a trap.
	hello := WindowsHello("unlock")
	if got := WithOrigin(hello, "https://x"); got.Name() != hello.Name() {
		t.Errorf("WithOrigin altered %s", hello.Name())
	}
}

// TestTheCrossPlatformConstraintIsWhatEarnsThePossessionClaim. Without it
// Windows may answer with the machine itself, and "something you have" would
// mean the computer already in front of the person.
func TestTheVerifiedFactorAsksForVerification(t *testing.T) {
	var seen keyFactor
	swap(t, nil, func(_ context.Context, f keyFactor) error { seen = f; return nil })

	if err := SecurityKey("e.test", nil).Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if seen.verify {
		t.Error("a plain security key asked for verification")
	}
	if err := VerifiedSecurityKey("e.test", nil).Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !seen.verify {
		t.Error("the verified factor did not ask for verification")
	}
}

func TestTheFactorsSayWhatTheyAre(t *testing.T) {
	for _, c := range []struct {
		f    mfa.Factor
		want string
	}{
		{WindowsHello("x"), "Windows Hello"},
		{SecurityKey("a", nil), "security key"},
	} {
		if !strings.Contains(c.f.Name(), c.want) {
			t.Errorf("Name() = %q, want it to mention %q", c.f.Name(), c.want)
		}
	}
}

func TestUnavailableWrapsBothWays(t *testing.T) {
	inner := errors.New("no verifier device")
	err := unavailable(inner)
	if !errors.Is(err, mfa.ErrUnavailable) {
		t.Error("the wrapper is not recognisable as unavailable")
	}
	if !errors.Is(err, inner) {
		t.Error("the wrapper lost the reason")
	}
}
