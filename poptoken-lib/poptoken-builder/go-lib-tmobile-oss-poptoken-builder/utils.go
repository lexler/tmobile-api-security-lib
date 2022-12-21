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
	"encoding/base64"
	"hash"
	"io"
	"net/http"
	"strings"

	jwt "github.com/golang-jwt/jwt/v4"
)

// concatHeaders handles the proper concatenation of headers appearing
// in the request.  It is passed the header name, the list of header
// values, and the list of keys; it returns the updated list of keys
// and the values to add to the digest.  Note that, if keys is nil,
// the returned value will be nil as well.
//
// This function is implemented in the fashion it is in order to allow
// it to be changed out to match the expectations of the applications
// that are expecting to receive PoP tokens.  This implementation
// assumes compliance with RFC 9110, but it is not clear that this is
// the correct assumption; so by centralizing this logic into one
// place, it becomes easier to update should that assumption prove
// incorrect.
func concatHeaders(name string, values, keys []string) ([]string, string) {
	// Note: this implementation assumes standards-compliant handling
	// of duplicated headers, with ", " as the joining string; see
	// section 5.3 of RFC 9110:
	//
	// https://www.rfc-editor.org/rfc/rfc9110.html#name-field-order
	//
	// Also, it is assumed that "Set-Cookie" does not appear in the
	// request headers, as that header is specified for response
	// headers and would require special handling with respect to this
	// section of RFC 9110.
	if keys != nil {
		keys = append(keys, name)
	}

	return keys, strings.Join(values, headerConcat)
}

// readBody is a helper to read a body from an [http.Request] and
// replace the body field with the as-read body.
func readBody(req *http.Request) ([]byte, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return []byte{}, err
	}

	// Replace the request's body
	req.Body = io.NopCloser(bytes.NewBuffer(body))

	return body, nil
}

// hashEncode is a helper that performs the task of massaging a
// hash.Hash into the correct base64-encoding.  For the purposes of
// the EDTS string, the base64 encoding must omit the trailing padding
// characters ("=").
func hashEncode(h hash.Hash) string {
	b64 := base64.URLEncoding.EncodeToString(h.Sum(nil))

	return strings.TrimRight(b64, "=")
}

// getClaim is a helper that extracts a claim from a [jwt.MapClaims]
// object.  It returns the value of the claim, and a boolean
// indicating if that claim was present and was a string.
func getClaim(claims jwt.MapClaims, claim string) (string, bool) {
	// Extract it from the claims object
	raw, ok := claims[claim]
	if !ok {
		return "", false
	}

	// Assert that it's a string
	str, ok := raw.(string)

	return str, ok
}
