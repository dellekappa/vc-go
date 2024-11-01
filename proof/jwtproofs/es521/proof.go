/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package es521

import (
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/veraison/go-cose"

	"github.com/dellekappa/vc-go/proof"
)

// Proof describes es521 proof type.
type Proof struct {
	supportedVMs []proof.SupportedVerificationMethod
}

const (
	// JWKKeyType for es521.
	JWKKeyType = "EC"
	// JWKCurve for es521.
	JWKCurve = "P-521"
	// JWTAlg for es521.
	JWTAlg = "ES521"
)

// New an instance of ed25519 proof type descriptor.
func New() *Proof {
	p := &Proof{}
	p.supportedVMs = []proof.SupportedVerificationMethod{
		{
			VerificationMethodType: "JsonWebKey2020",
			KMSKeyType:             kms.ECDSAP521TypeIEEEP1363,
			JWKKeyType:             JWKKeyType,
			JWKCurve:               JWKCurve,
			RequireJWK:             true,
		},
		{
			VerificationMethodType: "JsonWebKey2020",
			KMSKeyType:             kms.ECDSAP521TypeDER,
			JWKKeyType:             JWKKeyType,
			JWKCurve:               JWKCurve,
			RequireJWK:             true,
		},
	}

	return p
}

// SupportedVerificationMethods returns list of verification methods supported by this proof type.
func (s *Proof) SupportedVerificationMethods() []proof.SupportedVerificationMethod {
	return s.supportedVMs
}

// JWTAlgorithm return jwt alg that corresponds to VerificationMethod.
func (s *Proof) JWTAlgorithm() string {
	return JWTAlg
}

// CWTAlgorithm return cwt algorithm that corresponds to VerificationMethod.
func (s *Proof) CWTAlgorithm() cose.Algorithm {
	return 0
}
