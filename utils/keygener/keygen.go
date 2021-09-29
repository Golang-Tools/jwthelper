package keygener

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	mathrand "math/rand"
	"os"
	"strings"
)

//未知的算法错误
var ErrUnknownAlgoType = errors.New("unknown algo type")

//支持的算法类型
type AlgoType int32

const (
	AlgoType_RSA AlgoType = iota
	AlgoType_ECDSA
	AlgoType_ED25519
)

//StringTOAlgoType 将算法名转成算法枚举
func StringTOAlgoType(algoname string) (AlgoType, error) {
	switch strings.ToUpper(algoname) {
	case "RSA":
		{
			return AlgoType_RSA, nil
		}
	case "ECDSA":
		{
			return AlgoType_ECDSA, nil
		}
	case "ED25519":
		{
			return AlgoType_ED25519, nil
		}
	default:
		{
			return 0, ErrUnknownAlgoType
		}
	}
}

func saveAsPem(key interface{}, keyname string) error {
	//var block &pem.Block
	var block *pem.Block
	switch value := key.(type) {
	case *rsa.PrivateKey:
		{
			derStream := x509.MarshalPKCS1PrivateKey(value)
			block = &pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: derStream,
			}
			keyname = keyname + "_rsa.pem"

		}
	case *rsa.PublicKey:
		{
			defPkix, err := x509.MarshalPKIXPublicKey(value)
			if err != nil {
				return err
			}
			block = &pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: defPkix,
			}
			keyname = keyname + "_rsa_pub.pem"
		}
	case *ecdsa.PrivateKey:
		{
			derStream, err := x509.MarshalECPrivateKey(value)
			if err != nil {
				return err
			}
			block = &pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: derStream,
			}
			keyname = keyname + "_ecdsa.pem"
		}
	case *ecdsa.PublicKey:
		{
			defPkix, err := x509.MarshalPKIXPublicKey(value)
			if err != nil {
				return err
			}
			block = &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: defPkix,
			}
			keyname = keyname + "_ecdsa_pub.pem"
		}
	case *ed25519.PrivateKey:
		{
			derStream, err := x509.MarshalPKCS8PrivateKey(*value)
			if err != nil {
				return err
			}
			block = &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: derStream,
			}
			keyname = keyname + "_ed25519.pem"
		}
	case *ed25519.PublicKey:
		{
			{
				defPkix, err := x509.MarshalPKIXPublicKey(*value)
				if err != nil {
					return err
				}
				block = &pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: defPkix,
				}
				keyname = keyname + "_ed25519_pub.pem"
			}
		}
	default:
		{
			return ErrUnknownAlgoType
		}
	}
	file, err := os.Create(keyname)
	if err != nil {
		return err
	}
	defer file.Close()
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

// GenRsaKey 生成rsa公私钥对
func GenRsaKey(keyname string) error {
	bits := int(mathrand.Int31n(1000-250) + 250)
	//生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	err = saveAsPem(privateKey, keyname)
	if err != nil {
		return err
	}
	publicKey := &privateKey.PublicKey
	err = saveAsPem(publicKey, keyname)
	if err != nil {
		return err
	}
	return nil
}

// GenEcdsaKey 生成Ecdsa公私钥对
func GenEcdsaKey(keyname string) error {
	//生成私钥文件
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		return err
	}
	err = saveAsPem(privateKey, keyname)
	if err != nil {
		return err
	}
	publicKey := &privateKey.PublicKey
	err = saveAsPem(publicKey, keyname)
	if err != nil {
		return err
	}
	return nil
}

// GenEd25519Key 生成ed25519公私钥对
func GenEd25519Key(keyname string) error {
	//生成私钥文件
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	err = saveAsPem(&privateKey, keyname)
	if err != nil {
		return err
	}
	err = saveAsPem(&publicKey, keyname)
	if err != nil {
		return err
	}
	return nil
}

//GenKey 随机生成指定类型的公私钥对
func GenKey(algotype AlgoType, keyname string) error {
	switch algotype {
	case AlgoType_RSA:
		{
			return GenRsaKey(keyname)
		}
	case AlgoType_ECDSA:
		{
			return GenEcdsaKey(keyname)
		}
	case AlgoType_ED25519:
		{
			return GenEd25519Key(keyname)
		}
	default:
		{
			return ErrUnknownAlgoType
		}
	}
}
