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
	"crypto/subtle"
	"hash"
	"log"
	"net/http"
	"strings"
	"time"

	jwt "gopkg.in/dgrijalva/jwt-go.v3"
)

// Constants used internally.
const (
	defaultTTL = 2 * time.Minute

	// Keys for pseudo-headers
	uriKey    = "uri"
	methodKey = "http-method"
	bodyKey   = "body"

	// String used to concatenate repeated header values
	headerConcat = ", "

	// Header for PoP token
	popHeader = "X-Authorization"

	// Special claims for PoP token
	ehtsClaim = "ehts"
	edtsClaim = "edts"
)

// Logger is an interface used to control how logs generated within
// the library get reported.  Any object that implements a Printf
// function matching this signature can be used as a logger.
type Logger interface {
	// Printf formats a log message and sends it to the appropriate
	// log stream.
	Printf(format string, v ...interface{})
}

// HashFactory is a type describing a function that constructs and
// returns a [hash.Hash].  It can be used with the [HashConstructor]
// option to alter the hash algorithm used when constructing the EDTS
// string.
type HashFactory func() hash.Hash

// PoPToken is the type that implements the operations necessary to
// generate or validate a PoP token.  This structure contains the RSA
// keys, time-to-live option for the generated token, the logger, etc.
// Use the [New] function to generate a new PoPToken instance;
// [PoPToken.Build] and [PoPToken.Sign] are used for building tokens
// from [http.Request]; and [PoPToken.Verify] verifies a PoP token
// included in an [http.Request].
type PoPToken struct {
	privateKey    *rsa.PrivateKey // Private RSA key
	publicKey     *rsa.PublicKey  // Public RSA key
	hashConstruct HashFactory     // Function to construct a new hash.Hash
	debugFlag     bool            // Debugging flag
	ttl           time.Duration   // Time the token should live for
	logger        Logger          // Where logs should be sent
}

// New creates a new [PoPToken] instance from options passed in.  Use
// [PrivateKey] and [PublicKey] to set the private and/or public RSA
// keys; [HashConstructor] for setting the hash algorithm; [TTL] for
// altering the time-to-live of the resultant token from its 2 minute
// default; and [SetLogger] to provide an alternate logger from the
// default, which utilizes the standard [log] package.  Finally, the
// [Debug] option can be provided to enable debugging output.  At
// least one of the keys must be provided, or New will return
// [ErrNoKeys].  Further, if a private key is provided, the public
// key, if not provided, will be derived from it; or if the public key
// is provided, it will be validated to be associated with the private
// key and [ErrInvalidKeys] returned if that is not the case.
func New(opts ...Option) (*PoPToken, error) {
	obj := &PoPToken{
		hashConstruct: sha256.New,
		ttl:           defaultTTL,
		logger:        log.Default(),
	}

	// Apply the options
	for _, opt := range opts {
		opt.apply(obj)
	}

	// Make sure at least one key was provided and that the private
	// key matches the public key
	if obj.privateKey == nil && obj.publicKey == nil {
		return nil, ErrNoKeys
	}
	if obj.privateKey != nil && obj.publicKey != nil && !obj.privateKey.Public().(*rsa.PublicKey).Equal(obj.publicKey) {
		return nil, ErrInvalidKeys
	}
	if obj.privateKey != nil && obj.publicKey == nil {
		obj.publicKey = obj.privateKey.Public().(*rsa.PublicKey)
	}

	return obj, nil
}

// debugf is a helper for emitting debugging information.
func (pt *PoPToken) debugf(format string, v ...interface{}) {
	if pt.debugFlag {
		pt.logger.Printf(format, v...)
	}
}

// reqToEHTSAndEDTS takes a request and constructs the EHTS and EDTS
// strings that will then be used to construct the actual PoP token to
// be included in the request.
func (pt *PoPToken) reqToEHTSAndEDTS(req *http.Request) (string, string, error) {
	keys := []string{}
	valueHash := pt.hashConstruct()

	// Loop through the headers and construct the keys and values
	// appropriately
	for k, v := range req.Header {
		// Concatenate the header values
		var fullV string
		keys, fullV = concatHeaders(k, v, keys)

		pt.debugf("reqToEHTSAndEDTS: Processing header %q: %q", k, fullV)

		valueHash.Write([]byte(fullV))
	}

	// Add the URI and the method
	uri := req.URL.RequestURI()
	pt.debugf("reqToEHTSAndEDTS: Processing pseudo-header %q: %q", uriKey, uri)
	pt.debugf("reqToEHTSAndEDTS: Processing pseudo-header %q: %q", methodKey, req.Method)
	keys = append(keys, uriKey, methodKey)
	valueHash.Write([]byte(uri))
	valueHash.Write([]byte(req.Method))

	// Now add the body
	if req.Body != nil {
		body, err := readBody(req)
		if err != nil {
			return "", "", err
		}

		pt.debugf("reqToEHTSAndEDTS: Processing pseudo-header %q: %q", bodyKey, string(body))
		keys = append(keys, bodyKey)
		valueHash.Write(body)
	}

	ehts := strings.Join(keys, ";")
	edts := hashEncodePatch(valueHash)

	pt.debugf("reqToEHTSAndEDTS: Computed ehts: %q", ehts)
	pt.debugf("reqToEHTSAndEDTS: Computed edts: %q", edts)
	return ehts, edts, nil
}

// reqAndEHTSToEDTS is an alternative to reqToEHTSAndEDTS that is used
// for validating the EDTS hash field.  It is passed the request and
// an EHTS string--specifying the order of the fields--and
// recalculates the EDTS hash string.
func (pt *PoPToken) reqAndEHTSToEDTS(req *http.Request, ehts string) (string, error) {
	pt.debugf("reqAndEHTSToEDTS: Computing EDTS based on %q", ehts)

	valueHash := pt.hashConstruct()

	// Split the EHTS string and start accumulating the components
	for _, k := range strings.Split(ehts, ";") {
		switch k {
		case uriKey:
			uri := req.URL.RequestURI()
			pt.debugf("reqAndEHTSToEDTS: Processing pseudo-header %q: %q", uriKey, uri)
			valueHash.Write([]byte(uri))

		case methodKey:
			pt.debugf("reqAndEHTSToEDTS: Processing pseudo-header %q: %q", methodKey, req.Method)
			valueHash.Write([]byte(req.Method))

		case bodyKey:
			if req.Body != nil {
				body, err := readBody(req)
				if err != nil {
					return "", err
				}
				pt.debugf("reqAndEHTSToEDTS: Processing pseudo-header %q: %q", bodyKey, string(body))
				valueHash.Write(body)
			} else {
				pt.debugf("reqAndEHTSToEDTS: Pseudo-header %q listed, but no body", bodyKey)
			}

		default:
			// Concatenate the header values
			var fullV string
			_, fullV = concatHeaders(k, req.Header.Values(k), nil)

			pt.debugf("reqAndEHTSToEDTS: Processing header %q: %q", k, fullV)

			valueHash.Write([]byte(fullV))
		}
	}

	edts := hashEncodePatch(valueHash)

	pt.debugf("reqAndEHTSToEDTS: Computed edts: %q", edts)
	return edts, nil
}

// Build constructs and returns a PoP token for a given request.  If
// no private key has been provided, [ErrNoPrivateKey] will be
// returned.
func (pt *PoPToken) Build(req *http.Request) (string, error) {
	// Do we have a private key?
	if pt.privateKey == nil {
		return "", ErrNoPrivateKey
	}

	// Get the ehts and edts strings
	ehts, edts, err := pt.reqToEHTSAndEDTS(req)
	if err != nil {
		return "", err
	}

	// Prepare the PoP token with all claims specified by the PoP
	// token standard
	now := timeNow()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"v":       1,
		ehtsClaim: ehts,
		edtsClaim: edts,
		"iat":     now.Unix(),
		"exp":     now.Add(pt.ttl).Unix(),
		"jti":     uuidNew().String(),
	})

	// Generate the signed PoP token
	tok, err := token.SignedString(pt.privateKey)
	if err != nil {
		return "", err
	}

	pt.debugf("Build: Returning token %q", tok)

	return tok, nil
}

// Sign signs the request, setting the X-Authorization header to a
// valid PoP token value.  If no private key has been provided,
// [ErrNoPrivateKey] will be returned.
func (pt *PoPToken) Sign(req *http.Request) error {
	// Get the PoP token
	tok, err := pt.Build(req)
	if err != nil {
		return err
	}

	// Add the header
	pt.debugf("Sign: Setting %q header to token", popHeader)
	req.Header.Set(popHeader, tok)

	return nil
}

// Verify verifies that a request contains a valid, signed PoP token.
// It will return no error if the request is valid.  In the event the
// request contains no PoP token, it will return [ErrNoPoPToken].  Any
// other validation error will return an instance of the
// [InvalidToken] type, wrapping the underlying error.  (The use of
// [InvalidToken] is a security safety measure, intended to prevent
// leaking information to the request source about the cause of the
// error.)
func (pt *PoPToken) Verify(req *http.Request) error {
	// Get the raw token
	tok := req.Header.Get(popHeader)
	if tok == "" {
		pt.debugf("Verify: Header %q missing or no token present", popHeader)
		return ErrNoPoPToken
	}

	pt.debugf("Verify: Verifying token %q", tok)

	// Parse it
	token, err := jwtParse(tok, func(token *jwt.Token) (interface{}, error) {
		return pt.publicKey, nil
	})
	if err != nil {
		pt.debugf("Verify: jwt.Parse failed: %s", err)
		return wrapInvalidToken(err)
	} else if !token.Valid {
		pt.debugf("Verify: jwt.Parse marked token as invalid")
		return wrapInvalidToken(ErrParsedInvalid)
	}

	// Extract the claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		pt.debugf("Verify: jwt.Parse returned claims are not jwt.MapClaims")
		return wrapInvalidToken(ErrBadClaims)
	}

	// Now extract the "ehts" and "edts" strings
	ehts, ok := getClaim(claims, ehtsClaim)
	if !ok {
		pt.debugf("Verify: Claim %q missing or not a string", ehtsClaim)
		return wrapInvalidToken(ErrNoEHTSClaim)
	}
	edts, ok := getClaim(claims, edtsClaim)
	if !ok {
		pt.debugf("Verify: Claim %q missing or not a string", edtsClaim)
		return wrapInvalidToken(ErrNoEDTSClaim)
	}

	// Recompute the EDTS and see if it matches
	canonEDTS, err := pt.reqAndEHTSToEDTS(req, ehts)
	if err != nil {
		pt.debugf("Verify: Failed to recompute EDTS: %s", err)
		return wrapInvalidToken(err)
	}
	if subtle.ConstantTimeCompare([]byte(edts), []byte(canonEDTS)) != 1 {
		pt.debugf("Verify: Computed EDTS (%q) does not match claimed EDTS (%q)", canonEDTS, edts)
		return wrapInvalidToken(ErrEDTSMismatch)
	}

	// It's a valid token
	pt.debugf("Verify: Valid token")
	return nil
}
