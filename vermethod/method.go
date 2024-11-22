package vermethod

import "github.com/dellekappa/kcms-go/doc/jose/jwk"

// VerificationMethod is defined either as raw public key bytes (Value field) or as JSON Web Key.
type VerificationMethod struct {
	Type  string
	Value []byte
	JWK   *jwk.JWK
}
