package mdoc

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"time"
)

var (
	ErrInvalidCertificate = errors.New("invalid certificate")
	defaultCACerts        = []string{
		/*eudi utc*/ "308202dd30820283a0030201020214130c9b15cf49c3e6b3debd7cf0e8870dac427c71300a06082a8648ce3d040303305c311e301c06035504030c1550494420497373756572204341202d205554203032312d302b060355040a0c24455544492057616c6c6574205265666572656e636520496d706c656d656e746174696f6e310b3009060355040613025554301e170d3235303332343230323631345a170d3334303632303230323631335a305c311e301c06035504030c1550494420497373756572204341202d205554203032312d302b060355040a0c24455544492057616c6c6574205265666572656e636520496d706c656d656e746174696f6e310b30090603550406130255543059301306072a8648ce3d020106082a8648ce3d030107034200047ac0ca8fdac221cac68f4c1b49762f095f79ddb38f4982d91f94cd9a14f3db16bb55d96f42041e199460d4fac5e40170b74ef4c2f2fdaabd4350376f2e9e9ad6a38201213082011d30120603551d130101ff040830060101ff020100301f0603551d2304183016801462c7944728bd0fa21620a79ac2499444f101d3c730130603551d25040c300a06082b8102020000010730430603551d1f043c303a3038a036a034863268747470733a2f2f70726570726f642e706b692e65756469772e6465762f63726c2f7069645f43415f55545f30322e63726c301d0603551d0e0416041462c7944728bd0fa21620a79ac2499444f101d3c7300e0603551d0f0101ff040403020106305d0603551d1204563054865268747470733a2f2f6769746875622e636f6d2f65752d6469676974616c2d6964656e746974792d77616c6c65742f6172636869746563747572652d616e642d7265666572656e63652d6672616d65776f726b300a06082a8648ce3d04030303480030450221009ee11f6b3b8261169f36d643bc1a46fcad79b8a861bf7b9fce8b65e69d342a3902207c5b3e2c36e73f6fe3d4c078af067516019da6be28cab141f5d699c9121c3fdd",
		/*vcs dev*/ "308201bc30820163a00302010202143aff323b35be7439d7d07b9e355f3121fbad14c6300a06082a8648ce3d040302302f310b30090603550406130249543120301e06035504030c1756435320446576656c6f706d656e7420526f6f74204341301e170d3235303430313132353431385a170d3435303332373132353431385a302f310b30090603550406130249543120301e06035504030c1756435320446576656c6f706d656e7420526f6f742043413059301306072a8648ce3d020106082a8648ce3d03010703420004e86075b3fd0dae2ef85e455d47294fa23d3d2accc44a0d049a4ce6e6d8a4644f346a0e53a516a462438f48429ad82bdb1a140b7401f487229cc818cad48a87d4a35d305b300e0603551d0f0101ff04040302010630120603551d130101ff040830060101ff02010030160603551d250101ff040c300a06082b81020200000107301d0603551d0e04160414e373bca7095d0473e90131c32376d6b40ab1175d300a06082a8648ce3d04030203470030440220625d3400697db36f6c77e1971ac88e50eedb47f08db01c4dab68978bbb37cc2602203214da878149b51fcb2d182546a3951efec0bed62df303a92df393eb6aa9eddc",
	}
)

func verifyChain(
	rootCertificates []*x509.Certificate,
	chain []*x509.Certificate,
	now time.Time,
	checkRootCertificate func(rootCertificate *x509.Certificate) error,
	checkIntermediateCertificate func(certificate *x509.Certificate, previous *x509.Certificate) error,
	checkLeafCertificate func(certificate *x509.Certificate, previous *x509.Certificate) error,
) (*x509.Certificate, error) {
	var err error

	if len(rootCertificates) == 0 {
		return nil, ErrNoRootCertificates
	}

	chainLen := len(chain)
	if chainLen == 0 {
		return nil, ErrEmptyChain
	}

	// find & check root certificate
	var rootCertificate *x509.Certificate
	{
		firstCertificate := chain[0]
		for _, candidateRootCertificate := range rootCertificates {
			if err = checkCertificateSignature(firstCertificate, candidateRootCertificate); err == nil {
				rootCertificate = candidateRootCertificate
				break
			}
		}
		if rootCertificate == nil {
			return nil, ErrInvalidCertificate
		}
		if checkRootCertificate != nil {
			if err = checkRootCertificate(rootCertificate); err != nil {
				return nil, err
			}
		}
	}

	// check chain signatures
	previousCertificate := rootCertificate
	for _, certificate := range chain {
		if err = checkCertificateSignature(certificate, previousCertificate); err != nil {
			return nil, err
		}
		previousCertificate = certificate
	}

	// run extra checks on chain
	leafCertificate := previousCertificate
	previousCertificate = rootCertificate
	for _, certificate := range chain {
		if certificate != leafCertificate {
			if checkIntermediateCertificate != nil {
				if err = checkIntermediateCertificate(certificate, previousCertificate); err != nil {
					return nil, err
				}
			}
		} else {
			if checkLeafCertificate != nil {
				if err = checkLeafCertificate(certificate, previousCertificate); err != nil {
					return nil, err
				}
			}
		}
		previousCertificate = certificate
	}

	// check leaf certificate is current
	if err = checkCertificateValidity(leafCertificate, now); err != nil {
		return nil, err
	}

	return leafCertificate, nil
}

func checkCertificateSignature(certificate *x509.Certificate, signer *x509.Certificate) error {
	// issuer matches signer's subject
	if !bytes.Equal(certificate.RawIssuer, signer.RawSubject) {
		return ErrInvalidCertificate
	}

	// cert validity is within signer's validity
	if signer.NotAfter.Before(certificate.NotAfter) {
		return ErrInvalidCertificate
	}
	if signer.NotBefore.After(certificate.NotBefore) {
		return ErrInvalidCertificate
	}

	// signature valid
	if err := certificate.CheckSignatureFrom(signer); err != nil {
		return err
	}

	return nil
}

func checkCertificateValidity(certificate *x509.Certificate, now time.Time) error {
	// cert currently valid
	if now.After(certificate.NotAfter) {
		return ErrInvalidCertificate
	}
	if now.Before(certificate.NotBefore) {
		return ErrInvalidCertificate
	}

	return nil
}

// DefaultCACerts returns default root certificates
// Deprecated: hard coded ca certificates. This method will be removed soon
func DefaultCACerts() []*x509.Certificate {
	certs := make([]*x509.Certificate, len(defaultCACerts))
	for i, hexEncodedCert := range defaultCACerts {
		cacertDER, err := hex.DecodeString(hexEncodedCert)
		if err != nil {
			panic(err)
		}
		cacert, err := x509.ParseCertificate(cacertDER)
		if err != nil {
			panic(err)
		}
		certs[i] = cacert
	}

	return certs
}
