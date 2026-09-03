// Copyright (c) the go-mswin authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package factors

import (
	"context"
	"errors"
	"testing"

	"github.com/go-authn/mfa"
)

// TestOffWindowsBothFactorsAreAbsentRatherThanRefusing. A Mac has not failed
// anyone's Windows Hello; it has no Windows Hello.
func TestOffWindowsBothFactorsAreAbsent(t *testing.T) {
	for _, f := range []mfa.Factor{
		WindowsHello("unlock"),
		SecurityKey("example.test", nil),
	} {
		err := f.Verify(context.Background())
		if err == nil {
			t.Fatalf("%s succeeded off Windows", f.Name())
		}
		if !errors.Is(err, mfa.ErrUnavailable) {
			t.Errorf("%s = %v, want it to read as unavailable", f.Name(), err)
		}
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s lost the reason: %v", f.Name(), err)
		}
	}
}
