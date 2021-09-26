// 对称加密验证器
package jwtverifier

import (
	"github.com/Golang-Tools/jwthelper/errs"
	declare "github.com/Golang-Tools/jwthelper/jwtrpcdeclare"
	"github.com/Golang-Tools/jwthelper/utils"
	jwt "github.com/dgrijalva/jwt-go"
)

// Symmetric jwt的对称的加密验证器
type Symmetric struct {
	key string
	alg declare.EncryptionAlgorithm
}

// SymmetricNew 创建一个对称的加密验证器对象
func SymmetricNew(algo declare.EncryptionAlgorithm, key string) (*Symmetric, error) {
	if !utils.IsSymmetric(algo) {
		return nil, errs.ErrUnsupportAlgoType
	}
	verifier := &Symmetric{key: key, alg: algo}
	return verifier, nil
}
func (verifier *Symmetric) Alg() string {
	return verifier.alg.String()
}

// Verify 用Verifier对象验签
func (verifier *Symmetric) Verify(tokenstring string) (map[string]interface{}, error) {
	token, err := jwt.Parse(
		tokenstring,
		func(t *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if t.Method.Alg() != verifier.alg.String() {
				return nil, errs.ErrAlgoTypeNotMatch
			}
			return []byte(verifier.key), nil
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
