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
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"hash"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	private1 *rsa.PrivateKey
	private2 *rsa.PrivateKey
	public1  *rsa.PublicKey
	public2  *rsa.PublicKey
)

func init() {
	private1, _ = rsa.GenerateKey(rand.Reader, 2048)
	private2, _ = rsa.GenerateKey(rand.Reader, 2048)
	public1 = private1.Public().(*rsa.PublicKey)
	public2 = private2.Public().(*rsa.PublicKey)
}

func TestNewBase(t *testing.T) {
	opt1 := &mockOption{}
	opt1.On("apply", mock.Anything)
	opt2 := &mockOption{}
	opt2.On("apply", mock.Anything).Run(func(args mock.Arguments) {
		pt := args[0].(*PoPToken)
		pt.publicKey = public1
	})

	result, err := New(opt1, opt2)

	assert.NoError(t, err)
	assert.Nil(t, result.privateKey)
	assert.Equal(t, public1, result.publicKey)
	assert.Equal(t, defaultTTL, result.ttl)
	assert.Equal(t, log.Default(), result.logger)
	opt1.AssertExpectations(t)
	opt2.AssertExpectations(t)
}

func TestNewAutoDerivePublic(t *testing.T) {
	opt1 := &mockOption{}
	opt1.On("apply", mock.Anything)
	opt2 := &mockOption{}
	opt2.On("apply", mock.Anything).Run(func(args mock.Arguments) {
		pt := args[0].(*PoPToken)
		pt.privateKey = private1
	})

	result, err := New(opt1, opt2)

	assert.NoError(t, err)
	assert.Equal(t, private1, result.privateKey)
	assert.Equal(t, public1, result.publicKey)
	assert.Equal(t, defaultTTL, result.ttl)
	assert.Equal(t, log.Default(), result.logger)
	opt1.AssertExpectations(t)
	opt2.AssertExpectations(t)
}

func TestNewPrivateAndPublic(t *testing.T) {
	opt1 := &mockOption{}
	opt1.On("apply", mock.Anything)
	opt2 := &mockOption{}
	opt2.On("apply", mock.Anything).Run(func(args mock.Arguments) {
		pt := args[0].(*PoPToken)
		pt.privateKey = private1
		pt.publicKey = public1
	})

	result, err := New(opt1, opt2)

	assert.NoError(t, err)
	assert.Equal(t, private1, result.privateKey)
	assert.Equal(t, public1, result.publicKey)
	assert.Equal(t, defaultTTL, result.ttl)
	assert.Equal(t, log.Default(), result.logger)
	opt1.AssertExpectations(t)
	opt2.AssertExpectations(t)
}

func TestNewNoKeys(t *testing.T) {
	opt1 := &mockOption{}
	opt1.On("apply", mock.Anything)
	opt2 := &mockOption{}
	opt2.On("apply", mock.Anything)

	result, err := New(opt1, opt2)

	assert.ErrorIs(t, err, ErrNoKeys)
	assert.Nil(t, result)
	opt1.AssertExpectations(t)
	opt2.AssertExpectations(t)
}

func TestNewInvalidKeys(t *testing.T) {
	opt1 := &mockOption{}
	opt1.On("apply", mock.Anything)
	opt2 := &mockOption{}
	opt2.On("apply", mock.Anything).Run(func(args mock.Arguments) {
		pt := args[0].(*PoPToken)
		pt.privateKey = private1
		pt.publicKey = public2
	})

	result, err := New(opt1, opt2)

	assert.ErrorIs(t, err, ErrInvalidKeys)
	assert.Nil(t, result)
	opt1.AssertExpectations(t)
	opt2.AssertExpectations(t)
}

func TestPoPTokenDebugFBase(t *testing.T) {
	logger := &mockLogger{}
	obj := &PoPToken{
		logger: logger,
	}

	obj.debugf("this is a test: %s", "some arg")

	logger.AssertExpectations(t)
}

func TestPoPTokenDebugFDebugEnabled(t *testing.T) {
	logger := &mockLogger{}
	logger.On("Printf", "this is a test: %s", []interface{}{"some arg"})
	obj := &PoPToken{
		debugFlag: true,
		logger:    logger,
	}

	obj.debugf("this is a test: %s", "some arg")

	logger.AssertExpectations(t)
}

func TestPoPTokenReqToEHTSAndEDTSBase(t *testing.T) {
	value := &bytes.Buffer{}
	valueHash := &mockHash{}
	valueHash.On("Write", mock.Anything).Return(0, nil).Run(func(args mock.Arguments) {
		value.Write(args[0].([]byte))
	})
	obj := &PoPToken{
		hashConstruct: func() hash.Hash {
			return valueHash
		},
	}
	req := &http.Request{
		Method: "PUT",
		URL: &url.URL{
			Path: "/some/path",
		},
		Header: map[string][]string{
			"Content-Type": {"application/octet-stream"},
		},
	}
	patches := &mockPatches{}
	patches.On("hashEncode", mock.Anything).Return("hashed+string")
	patches.Install(t)

	ehts, edts, err := obj.reqToEHTSAndEDTS(req)

	assert.NoError(t, err)
	assert.Equal(t, "Content-Type;uri;http-method", ehts)
	assert.Equal(t, "hashed+string", edts)
	assert.Equal(t, "application/octet-stream/some/pathPUT", value.String())
	valueHash.AssertExpectations(t)
	patches.AssertExpectations(t)
}

func TestPoPTokenReqToEHTSAndEDTSWithBody(t *testing.T) {
	value := &bytes.Buffer{}
	valueHash := &mockHash{}
	valueHash.On("Write", mock.Anything).Return(0, nil).Run(func(args mock.Arguments) {
		value.Write(args[0].([]byte))
	})
	obj := &PoPToken{
		hashConstruct: func() hash.Hash {
			return valueHash
		},
	}
	req := &http.Request{
		Method: "PUT",
		URL: &url.URL{
			Path: "/some/path",
		},
		Header: map[string][]string{
			"Content-Type": {"application/octet-stream"},
		},
		Body: io.NopCloser(bytes.NewBuffer([]byte("this is a test"))),
	}
	patches := &mockPatches{}
	patches.On("hashEncode", mock.Anything).Return("hashed+string")
	patches.Install(t)

	ehts, edts, err := obj.reqToEHTSAndEDTS(req)

	assert.NoError(t, err)
	assert.Equal(t, "Content-Type;uri;http-method;body", ehts)
	assert.Equal(t, "hashed+string", edts)
	assert.Equal(t, "application/octet-stream/some/pathPUTthis is a test", value.String())
	valueHash.AssertExpectations(t)
	patches.AssertExpectations(t)
}

func TestPoPTokenReqToEHTSAndEDTSWithBadBody(t *testing.T) {
	value := &bytes.Buffer{}
	valueHash := &mockHash{}
	valueHash.On("Write", mock.Anything).Return(0, nil).Run(func(args mock.Arguments) {
		value.Write(args[0].([]byte))
	})
	obj := &PoPToken{
		hashConstruct: func() hash.Hash {
			return valueHash
		},
	}
	body := &mockReadCloser{}
	body.On("Read", mock.Anything).Return(0, assert.AnError)
	req := &http.Request{
		Method: "PUT",
		URL: &url.URL{
			Path: "/some/path",
		},
		Header: map[string][]string{
			"Content-Type": {"application/octet-stream"},
		},
		Body: body,
	}
	patches := &mockPatches{}
	patches.Install(t)

	ehts, edts, err := obj.reqToEHTSAndEDTS(req)

	assert.ErrorIs(t, err, assert.AnError)
	assert.Empty(t, ehts)
	assert.Empty(t, edts)
	assert.Equal(t, "application/octet-stream/some/pathPUT", value.String())
	valueHash.AssertExpectations(t)
	patches.AssertExpectations(t)
}

func TestPoPTokenReqAndEHTSToEDTSBase(t *testing.T) {
	value := &bytes.Buffer{}
	valueHash := &mockHash{}
	valueHash.On("Write", mock.Anything).Return(0, nil).Run(func(args mock.Arguments) {
		value.Write(args[0].([]byte))
	})
	obj := &PoPToken{
		hashConstruct: func() hash.Hash {
			return valueHash
		},
	}
	req := &http.Request{
		Method: "PUT",
		URL: &url.URL{
			Path: "/some/path",
		},
		Header: map[string][]string{
			"Content-Type": {"application/octet-stream"},
		},
		Body: io.NopCloser(bytes.NewBuffer([]byte("this is a test"))),
	}
	patches := &mockPatches{}
	patches.On("hashEncode", mock.Anything).Return("hashed+string")
	patches.Install(t)

	edts, err := obj.reqAndEHTSToEDTS(req, "Content-Type;uri;http-method;body")

	assert.NoError(t, err)
	assert.Equal(t, "hashed+string", edts)
	assert.Equal(t, "application/octet-stream/some/pathPUTthis is a test", value.String())
	valueHash.AssertExpectations(t)
	patches.AssertExpectations(t)
}

func TestPoPTokenReqAndEHTSToEDTSMissingBody(t *testing.T) {
	value := &bytes.Buffer{}
	valueHash := &mockHash{}
	valueHash.On("Write", mock.Anything).Return(0, nil).Run(func(args mock.Arguments) {
		value.Write(args[0].([]byte))
	})
	obj := &PoPToken{
		hashConstruct: func() hash.Hash {
			return valueHash
		},
	}
	req := &http.Request{
		Method: "PUT",
		URL: &url.URL{
			Path: "/some/path",
		},
		Header: map[string][]string{
			"Content-Type": {"application/octet-stream"},
		},
	}
	patches := &mockPatches{}
	patches.On("hashEncode", mock.Anything).Return("hashed+string")
	patches.Install(t)

	edts, err := obj.reqAndEHTSToEDTS(req, "Content-Type;uri;http-method;body")

	assert.NoError(t, err)
	assert.Equal(t, "hashed+string", edts)
	assert.Equal(t, "application/octet-stream/some/pathPUT", value.String())
	valueHash.AssertExpectations(t)
	patches.AssertExpectations(t)
}

func TestPoPTokenReqAndEHTSToEDTSBodyReadError(t *testing.T) {
	value := &bytes.Buffer{}
	valueHash := &mockHash{}
	valueHash.On("Write", mock.Anything).Return(0, nil).Run(func(args mock.Arguments) {
		value.Write(args[0].([]byte))
	})
	obj := &PoPToken{
		hashConstruct: func() hash.Hash {
			return valueHash
		},
	}
	body := &mockReadCloser{}
	body.On("Read", mock.Anything).Return(0, assert.AnError)
	req := &http.Request{
		Method: "PUT",
		URL: &url.URL{
			Path: "/some/path",
		},
		Header: map[string][]string{
			"Content-Type": {"application/octet-stream"},
		},
		Body: body,
	}
	patches := &mockPatches{}
	patches.Install(t)

	edts, err := obj.reqAndEHTSToEDTS(req, "Content-Type;uri;http-method;body")

	assert.ErrorIs(t, err, assert.AnError)
	assert.Empty(t, edts)
	assert.Equal(t, "application/octet-stream/some/pathPUT", value.String())
	valueHash.AssertExpectations(t)
	patches.AssertExpectations(t)
}

func TestPoPTokenBuildBase(t *testing.T) {
	valueHash := &mockHash{}
	valueHash.On("Write", mock.Anything).Return(0, nil)
	obj := &PoPToken{
		privateKey: private1,
		hashConstruct: func() hash.Hash {
			return valueHash
		},
		ttl: defaultTTL,
	}
	req := &http.Request{
		Method: "PUT",
		URL: &url.URL{
			Path: "/some/path",
		},
		Header: map[string][]string{
			"Content-Type": {"application/octet-stream"},
		},
	}
	now := time.Now()
	jti := uuid.New()
	patches := &mockPatches{}
	patches.On("hashEncode", mock.Anything).Return("hashed+string")
	patches.On("timeNow").Return(now)
	patches.On("uuidNew").Return(jti)
	patches.Install(t)

	result, err := obj.Build(req)

	assert.NoError(t, err)
	token, parseErr := jwt.Parse(result, func(token *jwt.Token) (interface{}, error) {
		return public1, nil
	})
	require.NoError(t, parseErr)
	assert.True(t, token.Valid)
	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, jwt.MapClaims{
		"v":       float64(1),
		ehtsClaim: "Content-Type;uri;http-method",
		edtsClaim: "hashed+string",
		"iat":     float64(now.Unix()),
		"exp":     float64(now.Add(defaultTTL).Unix()),
		"jti":     jti.String(),
	}, claims)
}

func TestPoPTokenBuildNoPrivateKey(t *testing.T) {
	valueHash := &mockHash{}
	obj := &PoPToken{
		hashConstruct: func() hash.Hash {
			return valueHash
		},
		ttl: defaultTTL,
	}
	req := &http.Request{
		Method: "PUT",
		URL: &url.URL{
			Path: "/some/path",
		},
		Header: map[string][]string{
			"Content-Type": {"application/octet-stream"},
		},
	}
	patches := &mockPatches{}
	patches.Install(t)

	result, err := obj.Build(req)

	assert.ErrorIs(t, err, ErrNoPrivateKey)
	assert.Empty(t, result)
}

func TestPoPTokenBuildBodyReadError(t *testing.T) {
	valueHash := &mockHash{}
	valueHash.On("Write", mock.Anything).Return(0, nil)
	obj := &PoPToken{
		privateKey: private1,
		hashConstruct: func() hash.Hash {
			return valueHash
		},
		ttl: defaultTTL,
	}
	body := &mockReadCloser{}
	body.On("Read", mock.Anything).Return(0, assert.AnError)
	req := &http.Request{
		Method: "PUT",
		URL: &url.URL{
			Path: "/some/path",
		},
		Header: map[string][]string{
			"Content-Type": {"application/octet-stream"},
		},
		Body: body,
	}
	patches := &mockPatches{}
	patches.Install(t)

	result, err := obj.Build(req)

	assert.ErrorIs(t, err, assert.AnError)
	assert.Empty(t, result)
}

func TestPoPTokenBuildSignFails(t *testing.T) {
	valueHash := &mockHash{}
	valueHash.On("Write", mock.Anything).Return(0, nil)
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: &big.Int{},
		},
	}
	obj := &PoPToken{
		privateKey: key,
		hashConstruct: func() hash.Hash {
			return valueHash
		},
		ttl: defaultTTL,
	}
	req := &http.Request{
		Method: "PUT",
		URL: &url.URL{
			Path: "/some/path",
		},
		Header: map[string][]string{
			"Content-Type": {"application/octet-stream"},
		},
	}
	now := time.Now()
	jti := uuid.New()
	patches := &mockPatches{}
	patches.On("hashEncode", mock.Anything).Return("hashed+string")
	patches.On("timeNow").Return(now)
	patches.On("uuidNew").Return(jti)
	patches.Install(t)

	result, err := obj.Build(req)

	assert.Error(t, err)
	assert.Empty(t, result)
}

func TestPoPTokenSignBase(t *testing.T) {
	valueHash := &mockHash{}
	valueHash.On("Write", mock.Anything).Return(0, nil)
	obj := &PoPToken{
		privateKey: private1,
		hashConstruct: func() hash.Hash {
			return valueHash
		},
		ttl: defaultTTL,
	}
	req := &http.Request{
		Method: "PUT",
		URL: &url.URL{
			Path: "/some/path",
		},
		Header: map[string][]string{
			"Content-Type": {"application/octet-stream"},
		},
	}
	now := time.Now()
	jti := uuid.New()
	patches := &mockPatches{}
	patches.On("hashEncode", mock.Anything).Return("hashed+string")
	patches.On("timeNow").Return(now)
	patches.On("uuidNew").Return(jti)
	patches.Install(t)

	err := obj.Sign(req)

	assert.NoError(t, err)
	require.Contains(t, req.Header, popHeader)
	token, parseErr := jwt.Parse(req.Header[popHeader][0], func(token *jwt.Token) (interface{}, error) {
		return public1, nil
	})
	require.NoError(t, parseErr)
	assert.True(t, token.Valid)
	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, jwt.MapClaims{
		"v":       float64(1),
		ehtsClaim: "Content-Type;uri;http-method",
		edtsClaim: "hashed+string",
		"iat":     float64(now.Unix()),
		"exp":     float64(now.Add(defaultTTL).Unix()),
		"jti":     jti.String(),
	}, claims)
}

func TestPoPTokenSignError(t *testing.T) {
	valueHash := &mockHash{}
	valueHash.On("Write", mock.Anything).Return(0, nil)
	obj := &PoPToken{
		privateKey: private1,
		hashConstruct: func() hash.Hash {
			return valueHash
		},
		ttl: defaultTTL,
	}
	body := &mockReadCloser{}
	body.On("Read", mock.Anything).Return(0, assert.AnError)
	req := &http.Request{
		Method: "PUT",
		URL: &url.URL{
			Path: "/some/path",
		},
		Header: map[string][]string{
			"Content-Type": {"application/octet-stream"},
		},
		Body: body,
	}
	patches := &mockPatches{}
	patches.Install(t)

	err := obj.Sign(req)

	assert.ErrorIs(t, err, assert.AnError)
	require.NotContains(t, req.Header, popHeader)
}

func TestPoPTokenVerifyBase(t *testing.T) {
	valueHash := &mockHash{}
	valueHash.On("Write", mock.Anything).Return(0, nil)
	obj := &PoPToken{
		publicKey: public1,
		hashConstruct: func() hash.Hash {
			return valueHash
		},
	}
	now := time.Now()
	jti := uuid.New()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"v":       1,
		ehtsClaim: "http-method",
		edtsClaim: "hashed+string",
		"iat":     now.Unix(),
		"exp":     now.Add(defaultTTL).Unix(),
		"jti":     jti.String(),
	})
	tok, _ := token.SignedString(private1)
	req := &http.Request{
		Method: "PUT",
		Header: map[string][]string{
			popHeader: {tok},
		},
	}
	patches := &mockPatches{}
	patches.On("hashEncode", mock.Anything).Return("hashed+string")
	patches.Install(t)

	err := obj.Verify(req)

	assert.NoError(t, err)
	valueHash.AssertExpectations(t)
	patches.AssertExpectations(t)
}

func TestPoPTokenVerifyNoHeader(t *testing.T) {
	valueHash := &mockHash{}
	obj := &PoPToken{
		publicKey: public1,
		hashConstruct: func() hash.Hash {
			return valueHash
		},
	}
	req := &http.Request{
		Method: "PUT",
		Header: map[string][]string{},
	}
	patches := &mockPatches{}
	patches.Install(t)

	err := obj.Verify(req)

	assert.ErrorIs(t, err, ErrNoPoPToken)
	valueHash.AssertExpectations(t)
	patches.AssertExpectations(t)
}

func TestPoPTokenVerifyEmptyHeader(t *testing.T) {
	valueHash := &mockHash{}
	obj := &PoPToken{
		publicKey: public1,
		hashConstruct: func() hash.Hash {
			return valueHash
		},
	}
	req := &http.Request{
		Method: "PUT",
		Header: map[string][]string{
			popHeader: {""},
		},
	}
	patches := &mockPatches{}
	patches.Install(t)

	err := obj.Verify(req)

	assert.ErrorIs(t, err, ErrNoPoPToken)
	valueHash.AssertExpectations(t)
	patches.AssertExpectations(t)
}

func TestPoPTokenVerifyUnparsableHeader(t *testing.T) {
	valueHash := &mockHash{}
	obj := &PoPToken{
		publicKey: public1,
		hashConstruct: func() hash.Hash {
			return valueHash
		},
	}
	req := &http.Request{
		Method: "PUT",
		Header: map[string][]string{
			popHeader: {"invalid value"},
		},
	}
	patches := &mockPatches{}
	patches.Install(t)

	err := obj.Verify(req)

	assert.Error(t, err)
	var invalTok InvalidToken
	assert.ErrorAs(t, err, &invalTok)
	valueHash.AssertExpectations(t)
	patches.AssertExpectations(t)
}

func TestPoPTokenVerifyInvalidToken(t *testing.T) {
	valueHash := &mockHash{}
	obj := &PoPToken{
		publicKey: public1,
		hashConstruct: func() hash.Hash {
			return valueHash
		},
	}
	now := time.Now()
	jti := uuid.New()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"v":       1,
		ehtsClaim: "http-method",
		edtsClaim: "hashed+string",
		"iat":     now.Unix(),
		"exp":     now.Add(defaultTTL).Unix(),
		"jti":     jti.String(),
	})
	tok, _ := token.SignedString(private1)
	req := &http.Request{
		Method: "PUT",
		Header: map[string][]string{
			popHeader: {tok},
		},
	}
	patches := &mockPatches{}
	patches.On("jwtParse", mock.Anything, mock.Anything, mock.Anything).Return(&jwt.Token{
		Valid: false,
	}, nil)
	patches.Install(t)
	patches.InstallJWTParse(t)

	err := obj.Verify(req)

	assert.ErrorIs(t, err, ErrParsedInvalid)
	var invalTok InvalidToken
	assert.ErrorAs(t, err, &invalTok)
	valueHash.AssertExpectations(t)
	patches.AssertExpectations(t)
}

func TestPoPTokenVerifyInvalidClaims(t *testing.T) {
	valueHash := &mockHash{}
	obj := &PoPToken{
		publicKey: public1,
		hashConstruct: func() hash.Hash {
			return valueHash
		},
	}
	now := time.Now()
	jti := uuid.New()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"v":       1,
		ehtsClaim: "http-method",
		edtsClaim: "hashed+string",
		"iat":     now.Unix(),
		"exp":     now.Add(defaultTTL).Unix(),
		"jti":     jti.String(),
	})
	tok, _ := token.SignedString(private1)
	req := &http.Request{
		Method: "PUT",
		Header: map[string][]string{
			popHeader: {tok},
		},
	}
	claims := &mockClaims{}
	patches := &mockPatches{}
	patches.On("jwtParse", mock.Anything, mock.Anything, mock.Anything).Return(&jwt.Token{
		Claims: claims,
		Valid:  true,
	}, nil)
	patches.Install(t)
	patches.InstallJWTParse(t)

	err := obj.Verify(req)

	assert.ErrorIs(t, err, ErrBadClaims)
	var invalTok InvalidToken
	assert.ErrorAs(t, err, &invalTok)
	valueHash.AssertExpectations(t)
	claims.AssertExpectations(t)
	patches.AssertExpectations(t)
}

func TestPoPTokenVerifyNoEHTS(t *testing.T) {
	valueHash := &mockHash{}
	obj := &PoPToken{
		publicKey: public1,
		hashConstruct: func() hash.Hash {
			return valueHash
		},
	}
	now := time.Now()
	jti := uuid.New()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"v":       1,
		edtsClaim: "hashed+string",
		"iat":     now.Unix(),
		"exp":     now.Add(defaultTTL).Unix(),
		"jti":     jti.String(),
	})
	tok, _ := token.SignedString(private1)
	req := &http.Request{
		Method: "PUT",
		Header: map[string][]string{
			popHeader: {tok},
		},
	}
	patches := &mockPatches{}
	patches.Install(t)

	err := obj.Verify(req)

	assert.ErrorIs(t, err, ErrNoEHTSClaim)
	var invalTok InvalidToken
	assert.ErrorAs(t, err, &invalTok)
	valueHash.AssertExpectations(t)
	patches.AssertExpectations(t)
}

func TestPoPTokenVerifyEHTSNotString(t *testing.T) {
	valueHash := &mockHash{}
	obj := &PoPToken{
		publicKey: public1,
		hashConstruct: func() hash.Hash {
			return valueHash
		},
	}
	now := time.Now()
	jti := uuid.New()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"v":       1,
		ehtsClaim: 15,
		edtsClaim: "hashed+string",
		"iat":     now.Unix(),
		"exp":     now.Add(defaultTTL).Unix(),
		"jti":     jti.String(),
	})
	tok, _ := token.SignedString(private1)
	req := &http.Request{
		Method: "PUT",
		Header: map[string][]string{
			popHeader: {tok},
		},
	}
	patches := &mockPatches{}
	patches.Install(t)

	err := obj.Verify(req)

	assert.ErrorIs(t, err, ErrNoEHTSClaim)
	var invalTok InvalidToken
	assert.ErrorAs(t, err, &invalTok)
	valueHash.AssertExpectations(t)
	patches.AssertExpectations(t)
}

func TestPoPTokenVerifyNoEDTS(t *testing.T) {
	valueHash := &mockHash{}
	obj := &PoPToken{
		publicKey: public1,
		hashConstruct: func() hash.Hash {
			return valueHash
		},
	}
	now := time.Now()
	jti := uuid.New()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"v":       1,
		ehtsClaim: "http-method",
		"iat":     now.Unix(),
		"exp":     now.Add(defaultTTL).Unix(),
		"jti":     jti.String(),
	})
	tok, _ := token.SignedString(private1)
	req := &http.Request{
		Method: "PUT",
		Header: map[string][]string{
			popHeader: {tok},
		},
	}
	patches := &mockPatches{}
	patches.Install(t)

	err := obj.Verify(req)

	assert.ErrorIs(t, err, ErrNoEDTSClaim)
	var invalTok InvalidToken
	assert.ErrorAs(t, err, &invalTok)
	valueHash.AssertExpectations(t)
	patches.AssertExpectations(t)
}

func TestPoPTokenVerifyEDTSNotString(t *testing.T) {
	valueHash := &mockHash{}
	obj := &PoPToken{
		publicKey: public1,
		hashConstruct: func() hash.Hash {
			return valueHash
		},
	}
	now := time.Now()
	jti := uuid.New()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"v":       1,
		ehtsClaim: "http-method",
		edtsClaim: 15,
		"iat":     now.Unix(),
		"exp":     now.Add(defaultTTL).Unix(),
		"jti":     jti.String(),
	})
	tok, _ := token.SignedString(private1)
	req := &http.Request{
		Method: "PUT",
		Header: map[string][]string{
			popHeader: {tok},
		},
	}
	patches := &mockPatches{}
	patches.Install(t)

	err := obj.Verify(req)

	assert.ErrorIs(t, err, ErrNoEDTSClaim)
	var invalTok InvalidToken
	assert.ErrorAs(t, err, &invalTok)
	valueHash.AssertExpectations(t)
	patches.AssertExpectations(t)
}

func TestPoPTokenVerifyBodyReadError(t *testing.T) {
	valueHash := &mockHash{}
	valueHash.On("Write", mock.Anything).Return(0, nil)
	obj := &PoPToken{
		publicKey: public1,
		hashConstruct: func() hash.Hash {
			return valueHash
		},
	}
	now := time.Now()
	jti := uuid.New()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"v":       1,
		ehtsClaim: "http-method;body",
		edtsClaim: "hashed+string",
		"iat":     now.Unix(),
		"exp":     now.Add(defaultTTL).Unix(),
		"jti":     jti.String(),
	})
	tok, _ := token.SignedString(private1)
	body := &mockReadCloser{}
	body.On("Read", mock.Anything).Return(0, assert.AnError)
	req := &http.Request{
		Method: "PUT",
		Header: map[string][]string{
			popHeader: {tok},
		},
		Body: body,
	}
	patches := &mockPatches{}
	patches.Install(t)

	err := obj.Verify(req)

	assert.ErrorIs(t, err, assert.AnError)
	var invalTok InvalidToken
	assert.ErrorAs(t, err, &invalTok)
	valueHash.AssertExpectations(t)
	patches.AssertExpectations(t)
}

func TestPoPTokenVerifyBadHash(t *testing.T) {
	valueHash := &mockHash{}
	valueHash.On("Write", mock.Anything).Return(0, nil)
	obj := &PoPToken{
		publicKey: public1,
		hashConstruct: func() hash.Hash {
			return valueHash
		},
	}
	now := time.Now()
	jti := uuid.New()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"v":       1,
		ehtsClaim: "http-method",
		edtsClaim: "hashed+string",
		"iat":     now.Unix(),
		"exp":     now.Add(defaultTTL).Unix(),
		"jti":     jti.String(),
	})
	tok, _ := token.SignedString(private1)
	req := &http.Request{
		Method: "PUT",
		Header: map[string][]string{
			popHeader: {tok},
		},
	}
	patches := &mockPatches{}
	patches.On("hashEncode", mock.Anything).Return("wrong+string")
	patches.Install(t)

	err := obj.Verify(req)

	assert.ErrorIs(t, err, ErrEDTSMismatch)
	var invalTok InvalidToken
	assert.ErrorAs(t, err, &invalTok)
	valueHash.AssertExpectations(t)
	patches.AssertExpectations(t)
}
