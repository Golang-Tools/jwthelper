package keygen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	mathrand "math/rand"
	"os"
)

func saveRSAAsPem(key interface{}, keyname string) error {
	//var block &pem.Block
	var block *pem.Block
	value, ok := key.(*rsa.PrivateKey)
	if !ok {
		value, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("Couldn't assert key")
		}
		defPkix, err := x509.MarshalPKIXPublicKey(value)
		if err != nil {
			return err
		}
		block = &pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: defPkix,
		}
		keyname = keyname + "_rsa_pub.pem"
	} else {
		derStream := x509.MarshalPKCS1PrivateKey(value)
		block = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: derStream,
		}
		keyname = keyname + "_rsa.pem"
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
func GenRsaKey(bits int, keyname string) error {
	//生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	err = saveRSAAsPem(privateKey, keyname)
	if err != nil {
		return err
	}
	publicKey := &privateKey.PublicKey
	err = saveRSAAsPem(publicKey, keyname)
	if err != nil {
		return err
	}
	return nil
}

// AutoGenRsaKey 随机生成一对rs256加密的密钥对
func AutoGenRsaKey() error {
	bits := int(mathrand.Int31n(1000-250) + 250)
	return GenRsaKey(bits, "autogen")
}
