# factors

[![Go Reference](https://pkg.go.dev/badge/github.com/go-mswin/factors.svg)](https://pkg.go.dev/github.com/go-mswin/factors)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-mswin/factors/actions/workflows/ci.yml/badge.svg)](https://github.com/go-mswin/factors/actions/workflows/ci.yml)

Windows's authentication factors, as factors —
[`mfa.Factor`](https://github.com/go-authn/mfa) values a policy can ask. Pure
Go, `CGO_ENABLED=0`.

```go
r, err := mfa.Verify(ctx, mfa.Policy{Count: 2},
    factors.WindowsHello("unlock the vault"),        // go-mswin/winrt
    factors.SecurityKey("example.test", credID),     // go-mswin/webauthn
)
```

The two factors come from **two different packages**, which is the shape of
Windows: [winrt](https://github.com/go-mswin/winrt) asks Windows Hello through
`UserConsentVerifier`, and [webauthn](https://github.com/go-mswin/webauthn)
asks a security key through `webauthn.dll`. Neither binding knows what a policy
is, and neither should — a program that only wants a Hello prompt must not end
up importing one.

## ⛔ Windows cannot offer an inherence factor

This is the finding that shapes the package, and it is worth stating plainly
rather than papering over.

**Windows Hello accepts a face, a fingerprint, or a PIN, and the person
chooses.** Nothing in `UserConsentVerifier` or in a WebAuthn assertion reports
*which* — the assertion's "user verified" bit is set the same way for all
three. A PIN is something *known*; a face is something one *is*. A factor
claiming `Inherence` here would be claiming to know something Windows never
said.

So `WindowsHello` reports **`mfa.Unknown`**, and a policy asking for distinct
*kinds* will never count it towards them. That is not this package working
around an API; it is the API declining to say, reported faithfully.

The consequence, worth knowing before designing around it:
**`mfa.Policy{Count: 2, DistinctKinds: true}` cannot be satisfied on Windows by
these two factors alone.** A caller who needs two kinds must supply the
knowledge factor themselves — and then it is theirs to be honest about. A test
holds this, so nobody quietly "fixes" it.

macOS *can* do better: LocalAuthentication has a biometrics-only policy, so
[go-macos/factors](https://github.com/go-macos/factors) offers a real inherence
factor. The difference between the two platforms is real, not an oversight
here.

## What earns the possession claim

`SecurityKey` constrains the request to a **cross-platform** authenticator, so
Windows Hello cannot answer it. Without that constraint Windows would be free
to satisfy the request with the machine itself, and *something you have* would
mean the computer already in front of the person.

And the constraint is a *request*. `Assertion.Transport` is an **observation**,
and the two can differ — so the answer is read back, and an authenticator that
reports itself as `internal` is refused even though it was asked not to be.
Silence is not a contradiction: an older Windows reports no transport at all,
and that is left alone rather than guessed at.

## What it refuses to confuse

- **Unavailable is not refused.** `winrt.Verify` is used rather than
  `RequireUserConsent`, because the latter folds every outcome into a boolean.
  `DeviceNotPresent`, `NotConfiguredForUser`, `DisabledByPolicy` and
  `DeviceBusy` are reported as `mfa.ErrUnavailable`; `Canceled` and
  `RetriesExhausted` came from somebody who was there and are refusals.
- **A PIN on the key is not a second factor.** `VerifiedSecurityKey` is still
  `Possession`: whatever the key asked for never reaches this machine and
  identifies nobody to us — it protects the key. Counting it separately would
  let one object masquerade as two factors.
- **The key must say a person was there.** The `UP` flag is checked, and `UV`
  when verification was asked for. Windows answering is not the same as
  somebody touching something.
- **The challenge is random.** This factor does not verify the signature, so
  there is no protocol to bind a challenge to — and a fixed one would let a
  recorded assertion be replayed here for ever.

## Coverage

Everything portable is covered to 100%, on Linux, with no hardware: the
classification, the kinds, the incomplete-request refusals, the origin default
and the absent-versus-refused split all go through the `askHello`/`askKey`
seams.

The two platform functions are not covered, and the gate says so rather than
pretending. They raise a Windows dialog and wait for a person; a runner has
nobody to touch a key and no Hello enrolled, and a test that popped a prompt
would be a test nobody could run twice. **They have not been run against a real
machine yet** — the packages underneath them have not either, and both say so.
