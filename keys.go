// 密钥提供者抽象与内置静态实现。
package jwthelper

import (
	"context"

	"github.com/Golang-Tools/jwthelper/v4/exceptions"
	jwt "github.com/golang-jwt/jwt/v4"
)

// SignerKeyProvider 提供签名密钥。
// SigningKey 应返回可直接用于指定算法签名的密钥:
// 对称算法(HS*)为 []byte,非对称算法为对应私钥(*ecdsa.PrivateKey/*rsa.PrivateKey/ed25519.PrivateKey)。
// 返回值会被缓存用于签名,实现可支持密钥轮换等动态来源。
type SignerKeyProvider interface {
	//SigningKey 返回指定算法的签名密钥
	SigningKey(ctx context.Context, algo Algo) (any, error)
}

// VerifierKeyProvider 提供校验密钥。
// VerificationKey 应返回可直接用于指定算法校验的密钥:
// 对称算法(HS*)为 []byte,非对称算法为对应公钥(*ecdsa.PublicKey/*rsa.PublicKey/ed25519.PublicKey)。
type VerifierKeyProvider interface {
	//VerificationKey 返回指定算法的校验密钥
	VerificationKey(ctx context.Context, algo Algo) (any, error)
}

// staticSignerKey 由内存中的密钥数据构造的签名密钥提供者
type staticSignerKey struct {
	algo Algo
	key  any
}

// SigningKey 返回构造时解析好的签名密钥
func (s staticSignerKey) SigningKey(ctx context.Context, algo Algo) (any, error) {
	return s.key, nil
}

// staticVerifierKey 由内存中的密钥数据构造的校验密钥提供者
type staticVerifierKey struct {
	algo Algo
	key  any
}

// VerificationKey 返回构造时解析好的校验密钥
func (s staticVerifierKey) VerificationKey(ctx context.Context, algo Algo) (any, error) {
	return s.key, nil
}

// NewSignerKey 由密钥原始数据创建静态签名密钥提供者
// raw 为对称密钥字节或pem编码的私钥,algo 用于决定解析方式
func NewSignerKey(raw []byte, algo Algo) (SignerKeyProvider, error) {
	key, err := parseSignerKey(raw, algo)
	if err != nil {
		return nil, err
	}
	return staticSignerKey{algo: algo, key: key}, nil
}

// NewVerifierKey 由密钥原始数据创建静态校验密钥提供者
// raw 为对称密钥字节或pem编码的公钥,algo 用于决定解析方式
func NewVerifierKey(raw []byte, algo Algo) (VerifierKeyProvider, error) {
	key, err := parseVerifierKey(raw, algo)
	if err != nil {
		return nil, err
	}
	return staticVerifierKey{algo: algo, key: key}, nil
}

// parseSignerKey 解析签名密钥:对称算法直接使用密钥字节,非对称算法解析pem私钥
func parseSignerKey(raw []byte, algo Algo) (any, error) {
	if IsAsymmetric(algo) {
		if IsEs(algo) {
			return jwt.ParseECPrivateKeyFromPEM(raw)
		}
		if IsRs(algo) {
			return jwt.ParseRSAPrivateKeyFromPEM(raw)
		}
		if IsEdDSA(algo) {
			return jwt.ParseEdPrivateKeyFromPEM(raw)
		}
		return nil, exceptions.ErrUnsupportAlgoType
	}
	if IsSymmetric(algo) {
		return raw, nil
	}
	return nil, exceptions.ErrUnsupportAlgoType
}

// parseVerifierKey 解析校验密钥:对称算法直接使用密钥字节,非对称算法解析pem公钥
func parseVerifierKey(raw []byte, algo Algo) (any, error) {
	if IsAsymmetric(algo) {
		if IsEs(algo) {
			return jwt.ParseECPublicKeyFromPEM(raw)
		}
		if IsRs(algo) {
			return jwt.ParseRSAPublicKeyFromPEM(raw)
		}
		if IsEdDSA(algo) {
			return jwt.ParseEdPublicKeyFromPEM(raw)
		}
		return nil, exceptions.ErrUnsupportAlgoType
	}
	if IsSymmetric(algo) {
		return raw, nil
	}
	return nil, exceptions.ErrUnsupportAlgoType
}
