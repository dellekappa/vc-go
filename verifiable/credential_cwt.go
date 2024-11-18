/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"

	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/veraison/go-cose"

	"github.com/dellekappa/vc-go/cwt"
	jsonutil "github.com/dellekappa/vc-go/util/json"
)

// CWTEnvelope contains information about CWT that envelops credential.
type CWTEnvelope struct {
	Sign1MessageRaw    []byte
	Sign1MessageParsed *cose.Sign1Message
}

// CWTClaims converts Verifiable Credential into CWT Credential claims, which can be than serialized.
type CWTClaims struct {
	Issuer    string               `json:"iss,omitempty"`
	Subject   string               `json:"sub,omitempty"`
	Audience  string               `json:"aud,omitempty"`
	Expiry    *josejwt.NumericDate `json:"exp,omitempty"`
	NotBefore *josejwt.NumericDate `json:"nbf,omitempty"`
	IssuedAt  *josejwt.NumericDate `json:"iat,omitempty"`
	Cti       []byte               `json:"cti,omitempty"`
	ID        string               `json:"-"`
}

// CWTCredClaims converts Verifiable Credential into CWT Credential claims, which can be than serialized.
type CWTCredClaims struct {
	*CWTClaims
	VC map[string]interface{} `json:"vc,omitempty"`
}

// CWTClaims converts Verifiable Credential into CWT Credential claims, which can be than serialized
// e.g. into JWS.
func (vc *Credential) CWTClaims() (*CWTCredClaims, error) {
	return newCWTCredClaims(vc)
}

// newJWTCredClaims creates JWT Claims of VC with an option to minimize certain fields of VC
// which is put into "vc" claim.
func newCWTCredClaims(vc *Credential) (*CWTCredClaims, error) {
	vcc := &vc.credentialContents

	subjectID, err := SubjectID(vcc.Subject)
	if err != nil {
		return nil, fmt.Errorf("get VC subject id: %w", err)
	}

	// currently jwt encoding supports only single subject (by the spec)
	claims := &CWTClaims{
		Issuer:    vcc.Issuer.ID,                           // iss
		NotBefore: josejwt.NewNumericDate(vcc.Issued.Time), // nbf
		ID:        vcc.ID,                                  // jti
		Subject:   subjectID,                               // sub
	}

	if vcc.Expired != nil {
		claims.Expiry = josejwt.NewNumericDate(vcc.Expired.Time) // exp
	}

	if vcc.Issued != nil {
		claims.IssuedAt = josejwt.NewNumericDate(vcc.Issued.Time)
	}

	credentialJSONCopy := jsonutil.ShallowCopyObj(vc.credentialJSON)

	credClaims := &CWTCredClaims{
		CWTClaims: claims,
		VC:        credentialJSONCopy,
	}

	return credClaims, nil
}

// MarshalCOSE serializes into signed form (COSE).
func (jcc *CWTCredClaims) MarshalCOSE(
	signatureAlg cose.Algorithm,
	signer cwt.ProofCreator,
	keyID string,
) ([]byte, *cose.Sign1Message, error) {
	return marshalCOSE(jcc, signatureAlg, signer, keyID)
}
