// Package hashwx executes the HashWX proof-of-work reference implementation.
//
// HashWX is a GPU-resistant proof-of-work function designed by tevador. Cap
// vendors the reference WebAssembly build; this package embeds the same binary
// and runs it with wazero so server-side verification is bit-identical to the
// JavaScript reference implementation.
//
// The embedded hashwx.wasm is licensed under the GNU Lesser General Public
// License v3.0; see LICENSE in this directory. Source:
// https://github.com/tevador/hashwx @ 74b567a31276a4c5d7cb232a5b7639467f49f961
package hashwx

import (
	"context"
	_ "embed"
	"errors"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed hashwx.wasm
var wasmBytes []byte

var (
	once    sync.Once
	runtime wazero.Runtime
	module  api.Module
	ctxPtr  uint64
	seedPtr uint64
	initErr error

	// callMu serializes access to the single wasm instance. HashWX keeps
	// mutable state in the instance's scratchpad, so concurrent calls would
	// otherwise race.
	callMu sync.Mutex
)

// Ready compiles and initializes the embedded HashWX module. It is called
// automatically on the first Hash; call it at boot to move the cost off the
// first request.
func Ready() error {
	once.Do(func() {
		ctx := context.Background()
		runtime = wazero.NewRuntime(ctx)

		mod, err := runtime.InstantiateWithConfig(ctx, wasmBytes, wazero.NewModuleConfig())
		if err != nil {
			initErr = err
			return
		}

		module = mod

		if init := mod.ExportedFunction("_initialize"); init != nil {
			if _, err := init.Call(ctx); err != nil {
				initErr = err
				return
			}
		}

		alloc := mod.ExportedFunction("hashwx_alloc")
		seedFn := mod.ExportedFunction("hashwx_seed")

		if alloc == nil || seedFn == nil {
			initErr = errors.New("hashwx: module is missing required exports")
			return
		}

		res, err := alloc.Call(ctx, 0) // HASHWX_INTERPRETED
		if err != nil {
			initErr = err
			return
		}

		ctxPtr = res[0]
		if ctxPtr == 0 {
			initErr = errors.New("hashwx: hashwx_alloc failed")
			return
		}

		res, err = seedFn.Call(ctx, ctxPtr)
		if err != nil {
			initErr = err
			return
		}

		seedPtr = res[0]
	})

	return initErr
}

// Hash runs the HashWX function generated from seed over nonce and returns the
// unsigned 64-bit result.
func Hash(seed [32]byte, nonce uint64) (uint64, error) {
	if err := Ready(); err != nil {
		return 0, err
	}

	callMu.Lock()
	defer callMu.Unlock()

	mem := module.Memory()
	if mem == nil {
		return 0, errors.New("hashwx: module has no memory")
	}

	if !mem.Write(uint32(seedPtr), seed[:]) {
		return 0, errors.New("hashwx: failed to write seed")
	}

	makeFn := module.ExportedFunction("hashwx_make")
	execFn := module.ExportedFunction("hashwx_exec")

	if makeFn == nil || execFn == nil {
		return 0, errors.New("hashwx: module is missing hash functions")
	}

	if _, err := makeFn.Call(context.Background(), ctxPtr, seedPtr); err != nil {
		return 0, err
	}

	res, err := execFn.Call(context.Background(), ctxPtr, nonce)
	if err != nil {
		return 0, err
	}

	return res[0], nil
}
