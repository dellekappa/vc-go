package verifiable

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/dellekappa/vc-go/cwt"
	"github.com/dellekappa/vc-go/mdoc"
	jsonutil "github.com/dellekappa/vc-go/util/json"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
	"time"
)

// MDocEnvelope contains information about MDoc that envelops credential.
type MDocEnvelope struct {
	MDocMessageRaw    []byte
	MDocMessageParsed *mdoc.IssuerSigned
}

// MDocCredClaims converts Verifiable Credential into MDoc Credential claims, which can be than serialized.
type MDocCredClaims struct {
	*mdoc.MobileSecurityObject
	claims mdoc.Claims
	VC     map[string]interface{} `json:"vc,omitempty"`
}

// MDocClaims converts Verifiable Credential into MDoc Credential claims, which can be than serialized
// e.g. into JWS.
func (vc *Credential) MDocClaims(hashAlg crypto.Hash) (*MDocCredClaims, error) {
	return newMDocCredClaims(vc, hashAlg)
}

// newMDocCredClaims creates JWT Claims of VC with an option to minimize certain fields of VC
// which is put into "vc" claim.
func newMDocCredClaims(vc *Credential, hashAlg crypto.Hash) (*MDocCredClaims, error) {
	vcc := &vc.credentialContents

	_, err := SubjectID(vcc.Subject)
	if err != nil {
		return nil, fmt.Errorf("get VC subject id: %w", err)
	}

	data := make(map[string]map[string]interface{})
	for k, v := range vcc.Subject[0].CustomFields {
		c, ok := v.(map[string]interface{})
		if !ok {
			return nil, errors.New("invalid type for mdoc claim data")
		}
		data[k] = c
	}

	holderKey, err := cose.NewKeyFromPublic(vcc.HolderKey)
	if err != nil {
		return nil, fmt.Errorf("cannot parse holder key: %w", err)
	}

	deviceKey := mdoc.DeviceKey(*holderKey)

	mso, claims, err := mdoc.NewMobileSecurityObject(data,
		mdoc.ValidityInfo{
			Signed:     time.Now().UTC(),
			ValidFrom:  vcc.Issued.Time.UTC(),
			ValidUntil: vcc.Expired.Time.UTC(),
		},
		mdoc.DeviceKeyInfo{
			DeviceKey: &deviceKey,
		},
		mdoc.DocType(vcc.Types[1]),
		hashAlg)
	if err != nil {
		return nil, fmt.Errorf("cannot create mobile security object: %w", err)
	}

	credentialJSONCopy := jsonutil.ShallowCopyObj(vc.credentialJSON)

	credClaims := &MDocCredClaims{
		MobileSecurityObject: mso,
		claims:               claims,
		VC:                   credentialJSONCopy,
	}

	return credClaims, nil
}

// MarshalIssuerSigned serializes into issuer signed MDOC object.
func (jcc *MDocCredClaims) MarshalIssuerSigned(
	signatureAlg cose.Algorithm,
	signer cwt.ProofCreator,
	_ string,
	certs []*x509.Certificate,
) ([]byte, *mdoc.IssuerSigned, error) {
	issuerAuth, err := mdoc.SignMobileSecurityObject(jcc.MobileSecurityObject, signatureAlg, signer, certs)
	if err != nil {
		return nil, nil, err
	}

	signed, err := mdoc.NewIssuerSigned(issuerAuth, jcc.claims)
	if err != nil {
		return nil, nil, err
	}

	encoded, err := cbor.Marshal(signed)
	if err != nil {
		return nil, nil, err
	}

	return encoded, &signed, nil
}

// MakeMDocOpts provides MDoc options for VC.
type MakeMDocOpts struct {
	hashAlg crypto.Hash
	certs   []*x509.Certificate
}

type MakeMDocOption func(opts *MakeMDocOpts)

// MakeMDocWithHash sets the hash to use for an MDoc VC.
func MakeMDocWithHash(hash crypto.Hash) MakeMDocOption {
	return func(opts *MakeMDocOpts) {
		opts.hashAlg = hash
	}
}

// MakeMDocWithCerts sets the x509 certs to use for an MDoc VC.
func MakeMDocWithCerts(certs []*x509.Certificate) MakeMDocOption {
	return func(opts *MakeMDocOpts) {
		opts.certs = certs
	}
}
