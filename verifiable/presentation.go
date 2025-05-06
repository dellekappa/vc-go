package verifiable

import (
	"github.com/dellekappa/vc-go/dataintegrity"
	jsonld "github.com/piprate/json-gold/ld"
)

const (
	// VPEnvelopedType indicates that the verifiable presentation is given as an enveloped verifiable presentation.
	// https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-presentations
	VPEnvelopedType = "EnvelopedVerifiablePresentation"

	// VPMediaTypeJWT is the media type for JWT-based verifiable presentations.
	// See https://www.w3.org/TR/vc-jose-cose/#vp-ld-json-jwt.
	VPMediaTypeJWT MediaType = "application/vp-ld+jwt"

	// VPMediaTypeSDJWT is the media type for selective disclosure JWT-based verifiable presentations.
	// See https://www.w3.org/TR/vc-jose-cose/#vp-ld-json-sd-jwt
	VPMediaTypeSDJWT MediaType = "application/vp-ld+sd-jwt"

	// VPMediaTypeCOSE is the media type for COSE-based verifiable presentations.
	// See https://www.w3.org/TR/vc-jose-cose/#vp-ld-json-cose.
	VPMediaTypeCOSE MediaType = "application/vp-ld+cose"
)

// CustomFields is a map of extra fields of struct build when unmarshalling JSON which are not
// mapped to the struct fields.
type CustomFields map[string]interface{}

type Presentation interface {
	// ID return current verifiable presentation ID
	ID() string
	// Credentials returns current credentials of presentation.
	Credentials() []*Credential
	// CustomFields returns a map with additional information
	CustomFields() CustomFields
}

// presentationOpts holds options for the Verifiable W3CPresentation decoding.
type presentationOpts struct {
	proofChecker        CombinedProofChecker
	disabledProofCheck  bool
	strictValidation    bool
	requireVC           bool
	requireProof        bool
	disableJSONLDChecks bool
	verifyDataIntegrity *verifyDataIntegrityOpts

	jsonldCredentialOpts
}

// PresentationOpt is the Verifiable W3CPresentation decoding option.
type PresentationOpt func(opts *presentationOpts)

func getPresentationOpts(opts []PresentationOpt) *presentationOpts {
	vpOpts := defaultPresentationOpts()

	for _, opt := range opts {
		opt(vpOpts)
	}

	return vpOpts
}

func defaultPresentationOpts() *presentationOpts {
	return &presentationOpts{
		verifyDataIntegrity: &verifyDataIntegrityOpts{},
	}
}

// WithPresProofChecker indicates that Verifiable W3CPresentation should be decoded from JWS using
// provided proofChecker.
func WithPresProofChecker(fetcher CombinedProofChecker) PresentationOpt {
	return func(opts *presentationOpts) {
		opts.proofChecker = fetcher
	}
}

// WithPresDisabledProofCheck option for disabling of proof check.
func WithPresDisabledProofCheck() PresentationOpt {
	return func(opts *presentationOpts) {
		opts.disabledProofCheck = true
	}
}

// WithPresStrictValidation enabled strict JSON-LD validation of VP.
// In case of JSON-LD validation, the comparison of JSON-LD VP document after compaction with original VP one is made.
// In case of mismatch a validation exception is raised.
func WithPresStrictValidation() PresentationOpt {
	return func(opts *presentationOpts) {
		opts.strictValidation = true
	}
}

// WithPresJSONLDDocumentLoader defines custom JSON-LD document loader. If not defined, when decoding VP
// a new document loader will be created using CachingJSONLDLoader() if JSON-LD validation is made.
func WithPresJSONLDDocumentLoader(documentLoader jsonld.DocumentLoader) PresentationOpt {
	return func(opts *presentationOpts) {
		opts.jsonldDocumentLoader = documentLoader
	}
}

// WithDisabledJSONLDChecks disables JSON-LD checks for VP parsing.
// By default, JSON-LD checks are enabled.
func WithDisabledJSONLDChecks() PresentationOpt {
	return func(opts *presentationOpts) {
		opts.disableJSONLDChecks = true
	}
}

// WithPresDataIntegrityVerifier provides the Data Integrity verifier to use when
// the presentation being processed has a Data Integrity proof.
func WithPresDataIntegrityVerifier(v *dataintegrity.Verifier) PresentationOpt {
	return func(opts *presentationOpts) {
		opts.verifyDataIntegrity.Verifier = v
	}
}

// WithPresExpectedDataIntegrityFields validates that a Data Integrity proof has the
// given purpose, domain, and challenge. Empty purpose means the default,
// assertionMethod, will be expected. Empty domain and challenge will mean they
// are not checked.
func WithPresExpectedDataIntegrityFields(purpose, domain, challenge string) PresentationOpt {
	return func(opts *presentationOpts) {
		opts.verifyDataIntegrity.Purpose = purpose
		opts.verifyDataIntegrity.Domain = domain
		opts.verifyDataIntegrity.Challenge = challenge
	}
}
