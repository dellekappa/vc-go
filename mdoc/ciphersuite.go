package mdoc

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
	"io"
	"math/big"
)

var (
	ErrUnsupportedCurve = errors.New("unsupported curve")
)

const (
	CipherSuiteVersion = 1
)

type Curve int

const (
	CurveP256 Curve = iota
	CurveP384
	CurveP521
	CurveX25519
	CurveX448
	CurveEd25519
	CurveEd448
	CurveBrainpoolP256r1
	CurveBrainpoolP320r1
	CurveBrainpoolP384r1
	CurveBrainpoolP512r1
)

var (
	SupportedCurves = [...]Curve{
		CurveP256,
		CurveP384,
		CurveP521,
		CurveX25519,
		CurveEd25519,
	}
)

type SDeviceKeyMode int

const (
	SDeviceKeyModeSign SDeviceKeyMode = iota
	SDeviceKeyModeMAC
)

func NewSDeviceKey(rand io.Reader, curve Curve, mode SDeviceKeyMode) (DeviceKeyPrivate, error) {
	if mode == SDeviceKeyModeSign {
		var c elliptic.Curve
		switch curve {
		case CurveP256:
			c = elliptic.P256()
		case CurveP384:
			c = elliptic.P384()
		case CurveP521:
			c = elliptic.P521()

		case CurveEd25519:
			_, key, err := ed25519.GenerateKey(rand)
			if err != nil {
				return nil, err
			}
			return (*deviceKeyPrivateEd25519)(&key), nil

		default:
			return nil, ErrUnsupportedCurve
		}

		key, err := ecdsa.GenerateKey(c, rand)
		if err != nil {
			return nil, err
		}
		return (*deviceKeyPrivateECDSA)(key), nil
	}

	if mode == SDeviceKeyModeMAC {
		var c ecdh.Curve
		switch curve {
		case CurveP256:
			c = ecdh.P256()
		case CurveP384:
			c = ecdh.P384()
		case CurveP521:
			c = ecdh.P521()
		case CurveX25519:
			c = ecdh.X25519()

		default:
			return nil, ErrUnsupportedCurve
		}

		key, err := c.GenerateKey(rand)
		if err != nil {
			return nil, err
		}
		return (*deviceKeyPrivateECDH)(key), nil
	}

	return nil, ErrUnsupportedCurve
}

func NewEDeviceKey(rand io.Reader, curve Curve) (DeviceKeyPrivate, error) {
	return NewSDeviceKey(rand, curve, SDeviceKeyModeMAC)
}

type DeviceKey cose.Key

func (dk *DeviceKey) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal((*cose.Key)(dk))
}

func (dk *DeviceKey) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, (*cose.Key)(dk))
}

func (dk *DeviceKey) publicKeyECDH() (*ecdh.PublicKey, error) {
	if dk.Type != cose.KeyTypeEC2 {
		return nil, ErrUnsupportedAlgorithm
	}

	crv, x, y, _ := (*cose.Key)(dk).EC2()

	curve, err := coseCurveToECDH(crv)
	if err != nil {
		return nil, err
	}

	lenX := len(x)
	point := make([]byte, 1+lenX+len(y))
	point[0] = 0x04

	copy(point[1:], x)
	copy(point[1+lenX:], y)

	return curve.NewPublicKey(point)
}

func (dk *DeviceKey) publicKeyECDSA() (*ecdsa.PublicKey, error) {
	if dk.Type != cose.KeyTypeEC2 {
		return nil, ErrUnsupportedAlgorithm
	}

	crv, x, y, _ := (*cose.Key)(dk).EC2()

	curve, err := coseCurveToElliptic(crv)
	if err != nil {
		return nil, err
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}

type DeviceKeyPrivate interface {
	DeviceKey() (*DeviceKey, error)
}

type deviceKeyPrivateECDH ecdh.PrivateKey

func (dk *deviceKeyPrivateECDH) DeviceKey() (*DeviceKey, error) {
	publicKey := (*ecdh.PrivateKey)(dk).PublicKey()

	curve, err := ecdhCurveToCOSE(publicKey.Curve())
	if err != nil {
		return nil, err
	}

	bytes := publicKey.Bytes()
	startY := len(bytes)/2 + 1
	x := bytes[1:startY]
	y := bytes[startY:]

	return &DeviceKey{
		Type: cose.KeyTypeEC2,
		Params: map[any]any{
			cose.KeyLabelEC2Curve: curve,
			cose.KeyLabelEC2X:     x,
			cose.KeyLabelEC2Y:     y,
		},
	}, nil
}

type deviceKeyPrivateECDSA ecdsa.PrivateKey

func (dk *deviceKeyPrivateECDSA) DeviceKey() (*DeviceKey, error) {
	key := (*ecdsa.PrivateKey)(dk).PublicKey

	curve, err := ellipticCurveToCose(key.Curve)
	if err != nil {
		return nil, err
	}

	return &DeviceKey{
		Type: cose.KeyTypeEC2,
		Params: map[any]any{
			cose.KeyLabelEC2Curve: curve,
			cose.KeyLabelEC2X:     key.X.Bytes(),
			cose.KeyLabelEC2Y:     key.Y.Bytes(),
		},
	}, nil
}

type deviceKeyPrivateEd25519 ed25519.PrivateKey

func (dk *deviceKeyPrivateEd25519) DeviceKey() (*DeviceKey, error) {
	key := (*ed25519.PrivateKey)(dk).Public().(ed25519.PublicKey)

	return &DeviceKey{
		Type: cose.KeyTypeOKP,
		Params: map[any]any{
			cose.KeyLabelOKPCurve: cose.CurveEd25519,
			cose.KeyLabelOKPX:     key,
		},
	}, nil
}

func coseCurveToECDH(curve cose.Curve) (ecdh.Curve, error) {
	switch curve {
	case cose.CurveP256:
		return ecdh.P256(), nil
	case cose.CurveP384:
		return ecdh.P384(), nil
	case cose.CurveP521:
		return ecdh.P521(), nil
	case cose.CurveX25519:
		return ecdh.X25519(), nil
	default:
		return nil, ErrUnsupportedCurve
	}
}

func coseCurveToElliptic(curve cose.Curve) (elliptic.Curve, error) {
	switch curve {
	case cose.CurveP256:
		return elliptic.P256(), nil
	case cose.CurveP384:
		return elliptic.P384(), nil
	case cose.CurveP521:
		return elliptic.P521(), nil
	default:
		return nil, ErrUnsupportedCurve
	}
}

func ecdhCurveToCOSE(curve ecdh.Curve) (cose.Curve, error) {
	switch curve {
	case ecdh.P256():
		return cose.CurveP256, nil
	case ecdh.P384():
		return cose.CurveP384, nil
	case ecdh.P521():
		return cose.CurveP521, nil
	case ecdh.X25519():
		return cose.CurveX25519, nil
	default:
		return cose.CurveReserved, ErrUnsupportedCurve
	}
}

func ellipticCurveToCose(curve elliptic.Curve) (cose.Curve, error) {
	switch curve {
	case elliptic.P256():
		return cose.CurveP256, nil
	case elliptic.P384():
		return cose.CurveP384, nil
	case elliptic.P521():
		return cose.CurveP521, nil
	default:
		return cose.CurveReserved, ErrUnsupportedCurve
	}
}
