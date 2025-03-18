package mdoc

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type Document struct {
	DocType      DocType       `cbor:"docType"`
	IssuerSigned IssuerSigned  `cbor:"issuerSigned"`
	DeviceSigned *DeviceSigned `cbor:"deviceSigned,omitempty"`
	Errors       Errors        `cbor:"errors,omitempty"`
}

type IssuerSigned struct {
	NameSpaces IssuerNameSpaces `cbor:"nameSpaces,omitempty"`
	IssuerAuth IssuerAuth       `cbor:"issuerAuth"`
}

type IssuerNameSpaces map[NameSpace]IssuerSignedItemBytes
type IssuerSignedItemBytes []TaggedEncodedCBOR

func (ins IssuerNameSpaces) Claims() (Claims, error) {
	namespacedClaims := make(Claims)
	for nameSpace, issuerSignedItems := range ins {
		claims := make([]Claim, len(issuerSignedItems))
		for i, issuerSignedItem := range issuerSignedItems {
			var claim Claim
			if err := cbor.Unmarshal(issuerSignedItem.UntaggedValue, &claim); err != nil {
				return nil, err
			}

			claim.nameSpace = nameSpace
			claims[i] = claim
		}
		namespacedClaims[nameSpace] = claims
	}
	return namespacedClaims, nil
}

type DeviceSigned struct {
	NameSpacesBytes TaggedEncodedCBOR `cbor:"nameSpaces"`
	DeviceAuth      DeviceAuth        `cbor:"deviceAuth"`
}

func (ds *DeviceSigned) NameSpaces() (*DeviceNameSpaces, error) {
	deviceNameSpaces := new(DeviceNameSpaces)
	if err := cbor.Unmarshal(ds.NameSpacesBytes.UntaggedValue, deviceNameSpaces); err != nil {
		return nil, err
	}

	return deviceNameSpaces, nil
}

func (ds *DeviceSigned) DeviceAuthenticationBytes(docType DocType, sessionTranscript []byte) ([]byte, error) {
	deviceAuthentication := []interface{}{
		"DeviceAuthentication",
		cbor.RawMessage(sessionTranscript),
		docType,
		cbor.Tag{Number: 24, Content: ds.NameSpaces},
	}
	da, err := cbor.Marshal(deviceAuthentication)
	if err != nil {
		return nil, fmt.Errorf("error encoding transcript: %v", err)
	}
	deviceAuthenticationByte, err := cbor.Marshal(cbor.Tag{Number: 24, Content: da})
	if err != nil {
		return nil, fmt.Errorf("failed to Marshal cbor %w", err)
	}
	return deviceAuthenticationByte, nil
}

type DeviceNameSpaces map[NameSpace]DeviceSignedItems
type DeviceSignedItems map[DataElementIdentifier]DataElementValue

type Errors map[NameSpace]ErrorItems
type ErrorItems map[DataElementIdentifier]ErrorCode
type ErrorCode int

func NewDocument(docType DocType, signed *cose.UntaggedSign1Message, claims Claims) (Document, error) {

	issuerSigned, err := NewIssuerSigned(signed, claims)
	if err != nil {
		return Document{}, err
	}

	return Document{
		DocType:      docType,
		IssuerSigned: issuerSigned,
	}, nil
}

func NewIssuerSigned(signed *cose.UntaggedSign1Message, claims Claims) (IssuerSigned, error) {
	encodedNamespaces := make(IssuerNameSpaces)
	for ns, values := range claims {
		encodedItems := make(IssuerSignedItemBytes, len(values))
		for i, v := range values {
			encodedItem, err := encodeModeTaggedEncodedCBOR.Marshal(&v)
			//encodedItem, err := cbor.Marshal(&v)
			if err != nil {
				return IssuerSigned{}, err
			}
			taggedEncodedItem, err := NewTaggedEncodedCBOR(encodedItem)
			if err != nil {
				return IssuerSigned{}, err
			}
			encodedItems[i] = *taggedEncodedItem
		}
		encodedNamespaces[ns] = encodedItems
	}

	return IssuerSigned{
		NameSpaces: encodedNamespaces,
		IssuerAuth: IssuerAuth(*signed),
	}, nil
}

type Claims map[NameSpace][]Claim

type Claim struct {
	Random            []byte                `cbor:"random"`
	DigestID          uint                  `cbor:"digestID"`
	ElementValue      DataElementValue      `cbor:"elementValue"`
	ElementIdentifier DataElementIdentifier `cbor:"elementIdentifier"`
	nameSpace         NameSpace
}

func newClaims(data map[string]map[string]interface{}) (Claims, error) {
	cborTags := map[string]uint64{
		"birth_date":    1004,
		"expiry_date":   1004,
		"issue_date":    1004,
		"issuance_date": 1004,
	}

	digestCount := uint(0)
	namespaces := make(Claims)
	for ns, values := range data {
		items := make([]Claim, 0)
		for k, v := range values {

			if t, ok := cborTags[k]; ok {
				v = cbor.Tag{
					Number:  t,
					Content: v,
				}
			}

			salt := make([]byte, 32)
			_, err := rand.Read(salt)
			if err != nil {
				return nil, err
			}

			item := Claim{
				DigestID:          digestCount,
				Random:            salt,
				ElementIdentifier: DataElementIdentifier(k),
				ElementValue:      v,
				nameSpace:         NameSpace(ns),
			}

			//cborItem, err := cbor.Marshal(&item)
			//if err != nil {
			//	return nil, err
			//}

			//taggedItem := cbor.Tag{
			//	Number: 24,
			//	Content: &item,
			//}

			items = append(items, item)

			digestCount++
		}
		namespaces[NameSpace(ns)] = items
	}

	return namespaces, nil
}

func (c *Claim) NameSpace() NameSpace {
	return c.nameSpace
}

func (c *Claim) CheckDigest(mso *MobileSecurityObject) error {
	if mso == nil {
		return errors.New("mso object is nil")
	}

	digests, found := mso.ValueDigests[c.nameSpace]
	if !found {
		return fmt.Errorf("mso does not contain digests for namespace '%s'", c.nameSpace)
	}

	digest, found := digests[DigestID(c.DigestID)]
	if !found {
		return fmt.Errorf("mso does not contain digest '%d' for namespace '%s'", c.DigestID, c.nameSpace)
	}

	hashAlg := mso.DigestAlgorithm
	var hash crypto.Hash
	switch hashAlg {
	case "SHA-256":
		hash = crypto.SHA256
	case "SHA-384":
		hash = crypto.SHA384
	case "SHA-512":
		hash = crypto.SHA512
	}

	hashed, err := digestValue(*c, hash)
	if err != nil {
		return fmt.Errorf("cannot hash claim '%s' for digest check: %w", c.ElementIdentifier, err)
	}

	if !bytes.Equal(digest, hashed) {
		return fmt.Errorf("invalid claim '%s'. The digest value doesn't match", c.ElementIdentifier)
	}

	return nil
}
