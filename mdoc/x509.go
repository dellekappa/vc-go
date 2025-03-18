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
		/*eudi utc*/ "3082031d308202a3a003020102021456a8e0b49a9fe21518264a9d6338bed31c21c056300a06082a8648ce3d040303305c311e301c06035504030c1550494420497373756572204341202d205554203031312d302b060355040a0c24455544492057616c6c6574205265666572656e636520496d706c656d656e746174696f6e310b3009060355040613025554301e170d3233303930313138333431375a170d3332313132373138333431365a305c311e301c06035504030c1550494420497373756572204341202d205554203031312d302b060355040a0c24455544492057616c6c6574205265666572656e636520496d706c656d656e746174696f6e310b30090603550406130255543076301006072a8648ce3d020106052b8104002203620004160e5285fb31a7947f505204292dcbdbb7709c58678d28148766ed28e4049df6f7768c9ea8c02f06d50c942961b05dee79f2a29c2c34f0d077d6bc02f9db63e97fcb1379f60bd8d138850df0fae794b4b942ce11b38654e4e220ceda1a3bc1bda38201243082012030120603551d130101ff040830060101ff020100301f0603551d23041830168014b36cb891171cd7a41a66318742e18bc040cc951b30160603551d250101ff040c300a06082b8102020000010730430603551d1f043c303a3038a036a034863268747470733a2f2f70726570726f642e706b692e65756469772e6465762f63726c2f7069645f43415f55545f30312e63726c301d0603551d0e04160414b36cb891171cd7a41a66318742e18bc040cc951b300e0603551d0f0101ff040403020106305d0603551d1204563054865268747470733a2f2f6769746875622e636f6d2f65752d6469676974616c2d6964656e746974792d77616c6c65742f6172636869746563747572652d616e642d7265666572656e63652d6672616d65776f726b300a06082a8648ce3d04030303680030650230697500de3fbec65fed743efab571160a291f33509a473e2fcc10bb352d3009d22d2a2cfa1d9795f043ed3429ec7caa4d023100aab75e2839ebe4ac1ff0103bb404de871365395e079dcd745ced5750bb62802c1be3d46992a952d87ba5f83a6a39b52c",
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
