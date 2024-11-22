/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/dellekappa/kcms-go/doc/jose"
)

// NewJOSESigner wraps ProofCreator into jose signer.
func NewJOSESigner(params SignParameters, signer ProofCreator) (*JoseSigner, error) {
	headers, err := signer.CreateJWTHeaders(params)
	if err != nil {
		return nil, err
	}

	return &JoseSigner{
		signer:     signer,
		signParams: params,
		headers:    headers,
	}, nil
}

// JoseSigner implement jose.proofCreator interface.
type JoseSigner struct {
	signer     ProofCreator
	signParams SignParameters
	headers    jose.Headers
}

// Sign returns signature.
func (s JoseSigner) Sign(data []byte) ([]byte, error) {
	return s.signer.SignJWT(s.signParams, data)
}

// Headers returns headers.
func (s JoseSigner) Headers() jose.Headers {
	return s.headers
}

type joseVerifier struct {
	proofChecker        ProofChecker
	expectedProofIssuer *string
}

func (v *joseVerifier) Verify(joseHeaders jose.Headers, _, signingInput, signature []byte) error {
	var expectedProofIssuer string

	if v.expectedProofIssuer != nil {
		expectedProofIssuer = *v.expectedProofIssuer
	} else {
		// if expectedProofIssuer not set, we get issuer DID from first part of key id.
		keyID, ok := joseHeaders.KeyID()
		if ok {
			expectedProofIssuer = strings.Split(keyID, "#")[0]
		} else {
			key, jwkOk := joseHeaders.JWK()
			if !jwkOk {
				return fmt.Errorf("missed kid or jwk in jwt header")
			}
			jwkJson, err := key.MarshalJSON()
			if err != nil {
				return fmt.Errorf("cannot marshar jwk in jwt header: %w", err)
			}
			expectedProofIssuer = fmt.Sprintf("did:jwk:%s", base64.URLEncoding.EncodeToString(jwkJson))
		}

	}

	return v.proofChecker.CheckJWTProof(joseHeaders, expectedProofIssuer, signingInput, signature)
}
