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
	"time"

	"github.com/google/uuid"
	jwt "gopkg.in/dgrijalva/jwt-go.v3"
)

// Functions to be patched out for testing.  These are internal
// functions.
var (
	hashEncodePatch = hashEncode
)

// Functions to be patched out for testing.  These are external
// functions from libraries.
var (
	timeNow  = time.Now
	uuidNew  = uuid.New
	jwtParse = jwt.Parse
)
