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
	"crypto/rsa"
	"time"
)

// Option represents an option for the New function.  This controls
// how PoPToken performs its tasks, including providing the private
// and public keys for generating and validating PoP tokens
// (respectively).
type Option interface {
	// apply applies the option.
	apply(obj *PoPToken)
}

// PrivateKeyOption is the implementation of the option returned by
// the [PrivateKey] constructor.
type PrivateKeyOption struct {
	privateKey *rsa.PrivateKey // The private key
}

// apply applies the option.
func (pk *PrivateKeyOption) apply(obj *PoPToken) {
	obj.privateKey = pk.privateKey
}

// PrivateKey is used to provide a private key for use by [PoPToken].
// This option must be passed in order for the [PoPToken.Build] and
// [PoPToken.Sign] operations to function.
func PrivateKey(pk *rsa.PrivateKey) *PrivateKeyOption {
	return &PrivateKeyOption{
		privateKey: pk,
	}
}

// PublicKeyOption is the implementation of the option returned by the
// [PublicKey] constructor.
type PublicKeyOption struct {
	publicKey *rsa.PublicKey // The public key
}

// apply applies the option.
func (pk *PublicKeyOption) apply(obj *PoPToken) {
	obj.publicKey = pk.publicKey
}

// PublicKey is used to provide a public key for use by [PoPToken].
func PublicKey(pk *rsa.PublicKey) *PublicKeyOption {
	return &PublicKeyOption{
		publicKey: pk,
	}
}

// HashConstructorOption is the implementation of the option returned
// by the [HashConstructor] constructor.
type HashConstructorOption struct {
	hc HashFactory // The hash constructor
}

// apply applies the option.
func (hco *HashConstructorOption) apply(obj *PoPToken) {
	obj.hashConstruct = hco.hc
}

// HashConstructor is used to provide a [hash.Hash] constructor for
// use by [PoPToken].  This option allows using a different hash
// algorithm than the default of SHA256.
func HashConstructor(hc HashFactory) *HashConstructorOption {
	return &HashConstructorOption{
		hc: hc,
	}
}

// DebugOption is the implementation of the [Debug] option.
type DebugOption bool

// apply applies the option.
func (do DebugOption) apply(obj *PoPToken) {
	obj.debugFlag = bool(do)
}

// Debug is an option that enables debugging output on the [PoPToken]
// object.
var Debug = DebugOption(true)

// TTL is an option that allows the time-to-live for the generated
// [PoPToken] to be altered from its default of 2 minutes.
type TTL time.Duration

// apply applies the option.
func (ttl TTL) apply(obj *PoPToken) {
	obj.ttl = time.Duration(ttl)
}

// LoggerOption is the implementation of the option returned by the
// [SetLogger] constructor.
type LoggerOption struct {
	logger Logger // The logger to use
}

// apply applies the option.
func (lo *LoggerOption) apply(obj *PoPToken) {
	obj.logger = lo.logger
}

// SetLogger is used to specify an alternative logger for use by
// [PoPToken].
func SetLogger(logger Logger) *LoggerOption {
	return &LoggerOption{
		logger: logger,
	}
}
