package mdoc

import (
	"crypto/rand"
	"github.com/fxamacker/cbor/v2"
)

type Claims map[NameSpace][]Claim

type Claim struct {
	DigestID          uint                  `cbor:"digestID"`
	Random            []byte                `cbor:"random"`
	ElementIdentifier DataElementIdentifier `cbor:"elementIdentifier"`
	ElementValue      DataElementValue      `cbor:"elementValue"`
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
