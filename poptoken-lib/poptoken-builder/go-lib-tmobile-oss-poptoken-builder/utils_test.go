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
	"crypto/sha256"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	jwt "gopkg.in/dgrijalva/jwt-go.v3"
)

func TestConcatHeadersBase(t *testing.T) {
	keys, value := concatHeaders("h2", []string{"h2v1"}, []string{"h1"})

	assert.Equal(t, []string{"h1", "h2"}, keys)
	assert.Equal(t, "h2v1", value)
}

func TestConcatHeadersMultiValue(t *testing.T) {
	keys, value := concatHeaders("h2", []string{"h2v1", "h2v2"}, []string{"h1"})

	assert.Equal(t, []string{"h1", "h2"}, keys)
	assert.Equal(t, "h2v1, h2v2", value)
}

func TestConcatHeadersNoKeys(t *testing.T) {
	keys, value := concatHeaders("h2", []string{"h2v1", "h2v2"}, nil)

	assert.Nil(t, keys)
	assert.Equal(t, "h2v1, h2v2", value)
}

func TestReadBodyBase(t *testing.T) {
	body := io.NopCloser(bytes.NewBuffer([]byte("this is a test")))
	req := &http.Request{
		Body: body,
	}

	result, err := readBody(req)

	assert.NoError(t, err)
	assert.Equal(t, []byte("this is a test"), result)
	assert.NotSame(t, req.Body, body)
	actual, _ := io.ReadAll(req.Body)
	assert.Equal(t, []byte("this is a test"), actual)
}

func TestReadBodyError(t *testing.T) {
	body := &mockReadCloser{}
	body.On("Read", mock.Anything).Return(0, assert.AnError)
	req := &http.Request{
		Body: body,
	}

	result, err := readBody(req)

	assert.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, []byte{}, result)
	body.AssertExpectations(t)
}

func TestHashEncode(t *testing.T) {
	h := sha256.New()
	h.Write([]byte("this is a test"))

	result := hashEncode(h)

	assert.Equal(t, "Lpl1hUiXKo6IIq1H-hAX_3Lwbz_2oBaFH0XDmHMrxQw", result)
}

func TestGetClaimBase(t *testing.T) {
	claims := jwt.MapClaims{
		"claim": "value",
	}

	result, ok := getClaim(claims, "claim")

	assert.True(t, ok)
	assert.Equal(t, "value", result)
}

func TestGetClaimNotString(t *testing.T) {
	claims := jwt.MapClaims{
		"claim": 10,
	}

	result, ok := getClaim(claims, "claim")

	assert.False(t, ok)
	assert.Equal(t, "", result)
}

func TestGetClaimMissing(t *testing.T) {
	claims := jwt.MapClaims{
		"claim": "value",
	}

	result, ok := getClaim(claims, "claim2")

	assert.False(t, ok)
	assert.Equal(t, "", result)
}
