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
	"crypto/sha256"
	"hash"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrivateKeyOptionImplementsOption(t *testing.T) {
	assert.Implements(t, (*Option)(nil), &PrivateKeyOption{})
}

func TestPrivateKeyOptionApply(t *testing.T) {
	key := &rsa.PrivateKey{}
	obj := &PrivateKeyOption{
		privateKey: key,
	}
	pt := &PoPToken{}

	obj.apply(pt)

	assert.Same(t, key, pt.privateKey)
}

func TestPrivateKey(t *testing.T) {
	key := &rsa.PrivateKey{}

	result := PrivateKey(key)

	require.NotNil(t, result)
	assert.Same(t, key, result.privateKey)
}

func TestPublicKeyOptionImplementsOption(t *testing.T) {
	assert.Implements(t, (*Option)(nil), &PublicKeyOption{})
}

func TestPublicKeyOptionApply(t *testing.T) {
	key := &rsa.PublicKey{}
	obj := &PublicKeyOption{
		publicKey: key,
	}
	pt := &PoPToken{}

	obj.apply(pt)

	assert.Same(t, key, pt.publicKey)
}

func TestPublicKey(t *testing.T) {
	key := &rsa.PublicKey{}

	result := PublicKey(key)

	require.NotNil(t, result)
	assert.Same(t, key, result.publicKey)
}

func TestHashConstructorOptionImplementsOption(t *testing.T) {
	assert.Implements(t, (*Option)(nil), &HashConstructorOption{})
}

func TestHashConstructorOptionApply(t *testing.T) {
	h := sha256.New()
	hc := func() hash.Hash {
		return h
	}
	obj := &HashConstructorOption{
		hc: hc,
	}
	pt := &PoPToken{}

	obj.apply(pt)

	// Note: function pointers cannot be directly compared, so we have
	// to call it and check the result is the same
	result := pt.hashConstruct()
	assert.Same(t, h, result)
}

func TestHashConstructor(t *testing.T) {
	h := sha256.New()
	hc := func() hash.Hash {
		return h
	}

	result := HashConstructor(hc)

	// Note: function pointers cannot be directly compared, so we have
	// to call it and check the result is the same
	r2 := result.hc()
	assert.Same(t, h, r2)
}

func TestDebugOptionImplementsOption(t *testing.T) {
	assert.Implements(t, (*Option)(nil), Debug)
}

func TestDebugOptionApply(t *testing.T) {
	pt := &PoPToken{}

	Debug.apply(pt)

	assert.True(t, pt.debugFlag)
}

func TestTTLImplementsOption(t *testing.T) {
	assert.Implements(t, (*Option)(nil), TTL(time.Second))
}

func TestTTLApply(t *testing.T) {
	obj := TTL(time.Second)
	pt := &PoPToken{}

	obj.apply(pt)

	assert.Equal(t, time.Second, pt.ttl)
}

func TestLoggerOptionImplementsOption(t *testing.T) {
	assert.Implements(t, (*Option)(nil), &LoggerOption{})
}

func TestLoggerOptionApply(t *testing.T) {
	logger := &mockLogger{}
	obj := &LoggerOption{
		logger: logger,
	}
	pt := &PoPToken{}

	obj.apply(pt)

	assert.Same(t, logger, pt.logger)
}

func TestSetLogger(t *testing.T) {
	logger := &mockLogger{}

	result := SetLogger(logger)

	assert.Same(t, logger, result.logger)
}
