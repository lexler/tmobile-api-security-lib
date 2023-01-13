# Go - PoP Token Builder Library

## Implementation Details

The T-Mobile PoP Token Builder library follows the following logic for creating the PoP token.

* Sets up the edts (external data to sign) / ehts (external headers to sign) claims in the PoP token using the headers in a provided HTTP request, joining repeated headers according to the algorithm described in [section 5.3 of RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#name-field-order).  The library uses SHA256 for calculating the edts and then the final edts value is encoded using Base64 URL encoding.
* Signs the PoP token using the specified RSA private key.
* Creates the PoP token with, by default, 2 minutes of validity.
* The PoP Token builder object is created by calling `New`, passing in options using the Go idiom of interface-based options; practically, a minimal call to generate this object looks like: `poptoken.New(poptoken.PrivateKey(privRSAKey))`.  Several options exist for customizing the operation.
* The PoP Token builder object can also be used to validate a received token; a minimal call to generate the object for this purpose looks like: `poptoken.New(poptoken.PublicKey(pubRSAKey))`.

Note: by default, all headers of an HTTP request are included when computing the PoP token for the request.  If some headers should not be protected, ensure that those headers are set _after_ calling `PoPToken.Sign`.
