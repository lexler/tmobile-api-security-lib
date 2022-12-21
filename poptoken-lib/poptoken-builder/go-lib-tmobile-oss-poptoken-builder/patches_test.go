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
	"hash"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/klmitch/patcher"
	"github.com/stretchr/testify/mock"
)

type mockPatches struct {
	mock.Mock
}

func (m *mockPatches) Install(t *testing.T) {
	p := patcher.NewPatchMaster(
		patcher.SetVar(&hashEncodePatch, m.hashEncode),
		patcher.SetVar(&timeNow, m.timeNow),
		patcher.SetVar(&uuidNew, m.uuidNew),
	).Install()
	t.Cleanup(func() {
		p.Restore()
	})
}

func (m *mockPatches) InstallJWTParse(t *testing.T) {
	p := patcher.SetVar(&jwtParse, m.jwtParse).Install()
	t.Cleanup(func() {
		p.Restore()
	})
}

func (m *mockPatches) hashEncode(h hash.Hash) string {
	args := m.Called(h)

	return args.String(0)
}

func (m *mockPatches) timeNow() time.Time {
	args := m.Called()

	if tmp := args.Get(0); tmp != nil {
		return tmp.(time.Time)
	}

	return time.Time{}
}

func (m *mockPatches) uuidNew() uuid.UUID {
	args := m.Called()

	if tmp := args.Get(0); tmp != nil {
		return tmp.(uuid.UUID)
	}

	return uuid.UUID{}
}

func (m *mockPatches) jwtParse(tokenString string, keyFunc jwt.Keyfunc, opts ...jwt.ParserOption) (*jwt.Token, error) {
	args := m.Called(tokenString, keyFunc, opts)

	if tmp := args.Get(0); tmp != nil {
		return tmp.(*jwt.Token), args.Error(1)
	}

	return nil, args.Error(1)
}
