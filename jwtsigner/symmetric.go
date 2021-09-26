// 对称加密的jjwt签名器
package jwtsigner

import (
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"

	"github.com/Golang-Tools/jwthelper/errs"
	declare "github.com/Golang-Tools/jwthelper/jwtrpcdeclare"
	"github.com/Golang-Tools/jwthelper/machineid"
	"github.com/Golang-Tools/jwthelper/options"
	utils "github.com/Golang-Tools/jwthelper/utils"
)

// Symmetric 对称加密签名器
type Symmetric struct {
	key  string
	alg  jwt.SigningMethod
	opts *options.SignerOptions
}

// SymmetricNew 创建一个非对称加密签名器对象
func SymmetricNew(algo declare.EncryptionAlgorithm, key string, opts ...options.SignerOption) (*Symmetric, error) {
	s := new(Symmetric)
	if !utils.IsSymmetric(algo) {
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

func (signer *Symmetric) Meta() *declare.MetaResponse {
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

func (signer *Symmetric) signany(claims jwt.MapClaims, opts ...options.SignOption) (string, error) {
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
	out, err := token.SignedString([]byte(signer.key))
	if err != nil {
		return "", err
	}
	return out, nil
}

//Sign 签名一个token
func (signer *Symmetric) Sign(payload []byte, opts ...options.SignOption) (string, error) {
	payloadclaims := jwt.MapClaims{}
	err := json.Unmarshal(payload, &payloadclaims)
	if err != nil {
		return "", err //ErrParseClaimsToJSON
	}
	return signer.signany(payloadclaims, opts...)
}
