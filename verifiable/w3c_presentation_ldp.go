/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"

	ldprocessor "github.com/dellekappa/did-go/doc/ld/processor"
)

// AddLinkedDataProof appends proof to the Verifiable W3CPresentation.
func (vp *W3CPresentation) AddLinkedDataProof(context *LinkedDataProofContext, jsonldOpts ...ldprocessor.Opts) error {
	raw, err := vp.raw()
	if err != nil {
		return fmt.Errorf("add linked data proof to VP: %w", err)
	}

	proofs, err := addLinkedDataProof(context, raw, jsonldOpts...)
	if err != nil {
		return err
	}

	vp.Proofs = proofs

	return nil
}
