// 非对称加密验证器
package jwtverifier

import (
	"regexp"

	"github.com/Golang-Tools/jwthelper/errs"
	declare "github.com/Golang-Tools/jwthelper/jwtrpcdeclare"
	utils "github.com/Golang-Tools/jwthelper/utils"

	jwt "github.com/dgrijalva/jwt-go"
)

// Asymmetric 非对称加密jwt的验证器
type Asymmetric struct {
	key interface{}
	alg jwt.SigningMethod
}

// asymmetricNew 创建一个非对称加密jwt的验证器对象
func asymmetricNew(algo declare.EncryptionAlgorithm, key interface{}) (*Asymmetric, error) {

	if !utils.IsAsymmetric(algo) {
		return nil, errs.ErrUnsupportAlgoType
	}
	alg := jwt.GetSigningMethod(algo.String())
	var verifier *Asymmetric
	verifier = &Asymmetric{
		key: key,
		alg: alg,
	}
	return verifier, nil
}

// AsymmetricFromPEM 使用PEM编码的密钥字节串创建一个非对称加密的jwt验证器对象
func AsymmetricFromPEM(algo declare.EncryptionAlgorithm, keybytes []byte) (*Asymmetric, error) {
	if utils.IsEs(algo) {
		key, err := jwt.ParseECPublicKeyFromPEM(keybytes)
		if err != nil {
			return nil, err
		}
		return asymmetricNew(algo, key)
	} else if utils.IsRs(algo) {
		key, err := jwt.ParseRSAPublicKeyFromPEM(keybytes)
		if err != nil {
			return nil, err
		}
		return asymmetricNew(algo, key)
	} else {
		return nil, errs.ErrUnsupportAlgoType
	}
}

// AsymmetricFromPEMFile 从路径上读取公钥文件创建一个Verifier对象
func AsymmetricFromPEMFile(algo declare.EncryptionAlgorithm, keyPath string) (*Asymmetric, error) {
	keybytes, err := utils.LoadData(keyPath)
	if err != nil {
		return nil, errs.ErrLoadPublicKey
	}
	return AsymmetricFromPEM(algo, keybytes)
}

func (verifier *Asymmetric) Alg() string {
	return verifier.alg.Alg()
}

// Verify 用Verifier对象验签
func (verifier *Asymmetric) Verify(tokenstring string) (map[string]interface{}, error) {
	tokenBytes := []byte(tokenstring)
	tokData := regexp.MustCompile(`\s*$`).ReplaceAll(tokenBytes, []byte{})
	token, err := jwt.Parse(
		string(tokData),
		func(t *jwt.Token) (interface{}, error) {
			return verifier.key, nil
		})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		var payload map[string]interface{} = claims
		return payload, nil
	}
	return nil, errs.ErrVerifyToken
}
