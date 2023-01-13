/*
 * Copyright 2022 Kevin L. Mitchell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package poptoken

import (
	"errors"
	"fmt"
)

// Errors that may be returned by the PoP token library.
var (
	ErrNoKeys       = errors.New("At least one of a public key or a private key must be provided")
	ErrInvalidKeys  = errors.New("Public key does not belong to private key")
	ErrNoPrivateKey = errors.New("No private key provided")
	ErrNoPoPToken   = errors.New("No PoP token set in request")

	// Invalid token errors; always wrapped in an InvalidToken
	ErrParsedInvalid = errors.New("Token marked as invalid by JWT library")
	ErrBadClaims     = errors.New("Token claims not interpretable")
	ErrNoEHTSClaim   = errors.New("EHTS claim not available or not a string")
	ErrNoEDTSClaim   = errors.New("EDTS claim not available or not a string")
	ErrEDTSMismatch  = errors.New("Computed EDTS does not match claimed EDTS")
)

// InvalidToken is an error that optionally wraps another error and
// which indicates that a token is not valid.
type InvalidToken struct {
	Err error // Wrapped error
}

// wrapInvalidToken is a helper that wraps an error with an
// [InvalidToken].
func wrapInvalidToken(e error) error {
	return InvalidToken{
		Err: e,
	}
}

// Error implements the error interface and returns the error string.
func (e InvalidToken) Error() string {
	return "PoP token is not valid"
}

// FullError returns the full error, including the embedded error.
// This is implemented as a non-standard error function to avoid
// leaking too much data to the client which originated the invalid
// token.
func (e InvalidToken) FullError() string {
	return fmt.Sprintf("PoP token is not valid: %s", e.Err)
}

// Unwrap implements the error unwrapping interface.
func (e InvalidToken) Unwrap() error {
	return e.Err
}

// FullError is a helper that reports the full error message of an
// error originating from the [PoPToken.Verify] method.  This ensures
// that the underlying cause of the verification error can be
// retrieved without accidentally leaking any data back to the client.
func FullError(e error) string {
	var ivError InvalidToken

	if errors.As(e, &ivError) {
		return ivError.FullError()
	}

	return e.Error()
}
