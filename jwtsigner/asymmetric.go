// 非对称算法的签名器
package jwtsigner

import (
	"crypto"
	"io"
	"strings"
	"time"

	"github.com/Golang-Tools/jwthelper/errs"
	declare "github.com/Golang-Tools/jwthelper/jwtrpcdeclare"
	"github.com/Golang-Tools/jwthelper/machineid"
	"github.com/Golang-Tools/jwthelper/options"
	utils "github.com/Golang-Tools/jwthelper/utils"
	jwt "github.com/dgrijalva/jwt-go"
)

// PrivateKey 非对称加密的私钥
type PrivateKey interface {
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

// Asymmetric 非对称加密签名器
type Asymmetric struct {
	key  PrivateKey
	alg  jwt.SigningMethod
	opts *options.SignerOptions
}

// AsymmetricNew 创建一个非对称加密签名器对象
func AsymmetricNew(algo declare.EncryptionAlgorithm, key PrivateKey, opts ...options.SignerOption) (*Asymmetric, error) {
	s := new(Asymmetric)
	if !utils.IsAsymmetric(algo) {
		return nil, errs.ErrUnsupportAlgoType
	}
	s.key = key
	alg := jwt.GetSigningMethod(algo.String())
	s.alg = alg
	builder := strings.Builder{}
	builder.Grow(len(machineid.MachineIDStr) + 1 + len(algo.String()))
	builder.WriteString(machineid.MachineIDStr)
	builder.WriteString("-")
	builder.WriteString(algo.String())
	s.opts = &options.SignerOptions{
		Iss:    builder.String(),
		JtiGen: options.DefaultSignerOptions.JtiGen,
	}
	for _, opt := range opts {
		opt.Apply(s.opts)
	}
	return s, nil
}

// AsymmetricFromPEM 使用PEM编码的密钥字节串创建一个非对称加密签名器对象
func AsymmetricFromPEM(algo declare.EncryptionAlgorithm, keybytes []byte, opts ...options.SignerOption) (*Asymmetric, error) {
	if utils.IsEs(algo) {
		key, err := jwt.ParseECPrivateKeyFromPEM(keybytes)
		if err != nil {
			return nil, err
		}
		return AsymmetricNew(algo, key)
	} else if utils.IsRs(algo) {
		key, err := jwt.ParseRSAPrivateKeyFromPEM(keybytes)
		if err != nil {
			return nil, err
		}
		return AsymmetricNew(algo, key, opts...)
	} else {
		return nil, errs.ErrUnsupportAlgoType
	}
}

// AsymmetricFromPEMFile 从路径上读取PEM私钥文件创建一个非对称加密签名器对象
func AsymmetricFromPEMFile(algo declare.EncryptionAlgorithm, keyPath string, opts ...options.SignerOption) (*Asymmetric, error) {
	keybytes, err := utils.LoadData(keyPath)
	if err != nil {
		return nil, errs.ErrLoadPrivateKey
	}
	return AsymmetricFromPEM(algo, keybytes, opts...)
}

func (signer *Asymmetric) Meta() *declare.MetaResponse {
	algo, err := utils.AlgoStrTOAlgoEnum(signer.alg.Alg())
	if err != nil {
		algo = declare.EncryptionAlgorithm_UNKNOWN
	}
	res := declare.MetaResponse{
		Iss:                      signer.opts.Iss,
		DefaultTTL:               int64(signer.opts.DefaultTTL),
		DefaultEffectiveInterval: int64(signer.opts.DefaultEffectiveInterval),
		JtiGen:                   signer.opts.JtiGen.String(),
		Algo:                     algo,
	}
	return &res
}

func (signer *Asymmetric) signany(claims jwt.MapClaims, opts ...options.SignOption) (string, error) {
	if signer.opts.Iss != "" {
		claims["iss"] = signer.opts.Iss
	}
	claims["iat"] = time.Now().Unix()
	if signer.opts.JtiGen != nil {
		jti, err := signer.opts.JtiGen.Next()
		if err == nil {
			claims["jti"] = jti
		} else {
			return "", err
		}
	}
	defaultopt := &options.SignOptions{}
	for _, opt := range opts {
		opt.Apply(defaultopt)
	}
	if defaultopt.Sub != "" {
		claims["sub"] = defaultopt.Sub
	}
	if defaultopt.Aud != nil {
		claims["aud"] = defaultopt.Aud
	}
	var nbr int64 = 0
	if defaultopt.Nbf != 0 {
		nbr = defaultopt.Nbf
	} else {
		if signer.opts.DefaultEffectiveInterval > 0 {
			nbr = time.Now().Add(signer.opts.DefaultEffectiveInterval).Unix()
		}
	}
	if defaultopt.Exp != 0 {
		claims["exp"] = defaultopt.Exp

	} else {
		if signer.opts.DefaultTTL > 0 {
			if nbr > 0 {
				claims["exp"] = time.Unix(nbr, 0).Add(signer.opts.DefaultTTL).Unix()
			} else {
				claims["exp"] = time.Now().Add(signer.opts.DefaultTTL).Unix()
			}
		}
	}
	if nbr > 0 {
		claims["nbf"] = nbr
	}

	token := jwt.NewWithClaims(signer.alg, claims)
	out, err := token.SignedString(signer.key)
	if err != nil {
		return "", err
	}
	return out, nil
}

//Sign 签名一个token
func (signer *Asymmetric) Sign(payload []byte, opts ...options.SignOption) (string, error) {
	payloadclaims := jwt.MapClaims{}
	err := json.Unmarshal(payload, &payloadclaims)
	if err != nil {
		return "", err //ErrParseClaimsToJSON
	}
	return signer.signany(payloadclaims, opts...)
}
