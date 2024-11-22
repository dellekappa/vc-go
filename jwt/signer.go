/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"github.com/dellekappa/kcms-go/doc/jose"
)

// SignParameters contains parameters of signing for jwt vc.
type SignParameters struct {
	KeyID             string
	JWTAlg            string
	AdditionalHeaders jose.Headers
}

// ProofCreator defines signer interface which is used to sign VC JWT.
type ProofCreator interface {
	SignJWT(params SignParameters, data []byte) ([]byte, error)
	CreateJWTHeaders(params SignParameters) (jose.Headers, error)
}
