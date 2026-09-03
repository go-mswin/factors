// Copyright (c) the go-mswin authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package factors

import (
	"context"
	"errors"
)

// ErrUnsupported is what both factors report off Windows. It is wrapped as
// unavailable rather than as a refusal: a Mac has not failed anyone's Windows
// Hello, it has no Windows Hello. The macOS adapters are go-macos/factors.
var ErrUnsupported = errors.New("factors: these are Windows factors")

func platformAskHello(context.Context, string) error  { return unavailable(ErrUnsupported) }
func platformAskKey(context.Context, keyFactor) error { return unavailable(ErrUnsupported) }
