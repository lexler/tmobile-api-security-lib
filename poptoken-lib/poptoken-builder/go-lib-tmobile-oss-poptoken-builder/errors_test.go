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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvalidTokenImplementsError(t *testing.T) {
	assert.Implements(t, (*error)(nil), InvalidToken{})
}

func TestWrapInvalidToken(t *testing.T) {
	result := wrapInvalidToken(assert.AnError)

	assert.Equal(t, InvalidToken{
		Err: assert.AnError,
	}, result)
}

func TestInvalidTokenError(t *testing.T) {
	obj := InvalidToken{}

	result := obj.Error()

	assert.Equal(t, "PoP token is not valid", result)
}

func TestInvalidTokenFullError(t *testing.T) {
	obj := InvalidToken{
		Err: assert.AnError,
	}

	result := obj.FullError()

	assert.Equal(t, fmt.Sprintf("PoP token is not valid: %s", assert.AnError), result)
}

func TestInvalidTokenUnwrap(t *testing.T) {
	obj := InvalidToken{
		Err: assert.AnError,
	}

	result := obj.Unwrap()

	assert.Equal(t, assert.AnError, result)
}

func TestFullErrorBase(t *testing.T) {
	result := FullError(assert.AnError)

	assert.Equal(t, assert.AnError.Error(), result)
}

func TestFullErrorWithInvalidToken(t *testing.T) {
	err := InvalidToken{
		Err: assert.AnError,
	}

	result := FullError(err)

	assert.Equal(t, fmt.Sprintf("PoP token is not valid: %s", assert.AnError), result)
}
