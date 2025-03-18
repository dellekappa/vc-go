/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	util "github.com/dellekappa/did-go/doc/util/time"
	"github.com/dellekappa/vc-go/mdoc"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"time"
)

type MDocPresentation struct {
	id              string
	rawPresentation []byte
	credentials     []*Credential
	customFields    CustomFields
}

// ParseMDocPresentation creates an instance of Verifiable W3CPresentation by reading a JSON document from bytes.
// It also applies miscellaneous options like custom decoders or settings of schema validation.
func ParseMDocPresentation(vpData []byte, opts ...PresentationOpt) (*MDocPresentation, error) {
	//vpOpts := getPresentationOpts(opts)

	data, err := base64.RawURLEncoding.DecodeString(string(vpData))
	if err != nil {
		return nil, fmt.Errorf("cannot b64 decode MDoc Verifiable Presentation: %w", err)
	}
	// todo proof checker !!

	var message mdoc.DeviceResponse

	if err = cbor.Unmarshal(data, &message); err != nil {
		return nil, fmt.Errorf("cannot unmarshal MDoc Verifiable Presentation: %w", err)
	}

	credentials := make([]*Credential, 0, len(message.Documents))
	for _, d := range message.Documents {
		//chain, err := d.IssuerSigned.IssuerAuth.X509Chain()
		//if err != nil {
		//	return nil, fmt.Errorf("cannot parse MDoc Verifiable Presentation issuer auth x509 chain: %w", err)
		//}

		err := d.IssuerSigned.IssuerAuth.Verify(mdoc.DefaultCACerts(), time.Now())
		if err != nil {
			return nil, fmt.Errorf("cannot verify MDoc Verifiable Presentation: %w", err)
		}

		mso, err := d.IssuerSigned.IssuerAuth.MobileSecurityObject()
		if err != nil {
			return nil, fmt.Errorf("cannot extract mso from MDoc Verifiable Presentation: %w", err)
		}

		claims, err := d.IssuerSigned.NameSpaces.Claims()
		if err != nil {
			return nil, fmt.Errorf("cannot parse MDoc Verifiable Presentation Claims: %w", err)
		}

		vcContent := make(map[string]interface{}, len(claims))
		for ns, cls := range claims {
			nsContent := make(map[string]interface{}, len(cls))
			for _, v := range cls {
				err = v.CheckDigest(mso)
				if err != nil {
					return nil, fmt.Errorf("cannot parse MDoc Verifiable Presentation Claims: %w", err)
				}

				claimName := string(v.ElementIdentifier)
				claimValue := v.ElementValue
				nsContent[claimName] = claimValue
			}
			vcContent[string(ns)] = nsContent
		}

		// TODO: da verificare
		cred := &Credential{
			credentialJSON: vcContent,
			credentialContents: CredentialContents{
				//	Context:        nil,
				//	CustomContext:  nil,
				//	ID:             "",
				//	Types:          nil,
				//	Subject:        nil,
				//	Issuer:         nil,
				Issued:  util.NewTime(mso.ValidityInfo.ValidFrom),
				Expired: util.NewTime(mso.ValidityInfo.ValidUntil),
				//	Status:         nil,
				//	Schemas:        nil,
				//	Evidence:       nil,
				//	TermsOfUse:     nil,
				//	RefreshService: nil,
				//	SDJWTHashAlg:   nil,
				//	HolderKey:      nil,
			},
			MDocEnvelope: &MDocEnvelope{
				MDocMessageParsed: &d.IssuerSigned,
			},
		}

		credentials = append(credentials, cred)
	}

	return &MDocPresentation{
		id:              uuid.New().String(),
		rawPresentation: data,
		credentials:     credentials,
	}, nil
}

func (p *MDocPresentation) Hex() string {
	return hex.EncodeToString(p.rawPresentation)
}

func (p *MDocPresentation) B64() string {
	return base64.RawURLEncoding.EncodeToString(p.rawPresentation)
}

func (p *MDocPresentation) ID() string {
	return p.id
}

func (p *MDocPresentation) Credentials() []*Credential {
	return p.credentials
}

func (p *MDocPresentation) CustomFields() CustomFields {
	if p.customFields == nil {
		p.customFields = map[string]interface{}{}
	}
	return p.customFields
}
