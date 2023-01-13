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

import "github.com/stretchr/testify/mock"

type mockOption struct {
	mock.Mock
}

func (m *mockOption) apply(obj *PoPToken) {
	m.Called(obj)
}

type mockLogger struct {
	mock.Mock
}

func (m *mockLogger) Printf(format string, v ...interface{}) {
	m.Called(format, v)
}

type mockReadCloser struct {
	mock.Mock
}

func (m *mockReadCloser) Read(p []byte) (int, error) {
	args := m.Called(p)

	return args.Int(0), args.Error(1)
}

func (m *mockReadCloser) Close() error {
	args := m.Called()

	return args.Error(0)
}

type mockHash struct {
	mock.Mock
}

func (m *mockHash) Write(p []byte) (int, error) {
	args := m.Called(p)

	return args.Int(0), args.Error(1)
}

func (m *mockHash) Sum(b []byte) []byte {
	args := m.Called(b)

	if tmp := args.Get(0); tmp != nil {
		return tmp.([]byte)
	}

	return nil
}

func (m *mockHash) Reset() {
	m.Called()
}

func (m *mockHash) Size() int {
	args := m.Called()

	return args.Int(0)
}

func (m *mockHash) BlockSize() int {
	args := m.Called()

	return args.Int(0)
}

type mockClaims struct {
	mock.Mock
}

func (m *mockClaims) Valid() error {
	args := m.Called()

	return args.Error(0)
}
