// signer jwt的签名器

package jwthelper

import (
	"time"

	"github.com/Golang-Tools/jwthelper/exceptions"
	"github.com/Golang-Tools/jwthelper/jwt_pb"
	"github.com/Golang-Tools/jwthelper/signoptions"
	utils "github.com/Golang-Tools/jwthelper/utils"
	jwt "github.com/golang-jwt/jwt/v4"
)

type Signer struct {
	algo jwt.SigningMethod
	key  interface{}
	opts SignerOptions
}

// NewSigner 创建一个签名器对象
func NewSigner(opts ...SignerOption) (*Signer, error) {
	s := new(Signer)
	s.opts = DefaultSignerOptions
	for _, opt := range opts {
		opt.Apply(&s.opts)
	}
	if !utils.IsAsymmetric(s.opts.Algo) && !utils.IsSymmetric(s.opts.Algo) {
		return nil, exceptions.ErrUnsupportAlgoType
	}
	algo := jwt.GetSigningMethod(s.opts.Algo.String())
	s.algo = algo
	if utils.IsAsymmetric(s.opts.Algo) {
		if utils.IsEs(s.opts.Algo) {
			key, err := jwt.ParseECPrivateKeyFromPEM(s.opts.Key)
			if err != nil {
				return nil, err
			}
			s.key = key
		} else if utils.IsRs(s.opts.Algo) {
			key, err := jwt.ParseRSAPrivateKeyFromPEM(s.opts.Key)
			if err != nil {
				return nil, err
			}
			s.key = key
		} else {
			return nil, exceptions.ErrUnsupportAlgoType
		}
	} else {
		s.key = s.opts.Key
	}
	return s, nil
}

//Meta 获取签名器元数据
func (signer *Signer) Meta() *jwt_pb.SignerMeta {
	return &jwt_pb.SignerMeta{
		Algo:                     signer.opts.Algo,
		Iss:                      signer.opts.Iss,
		DefaultTTL:               int64(signer.opts.DefaultTTL.Seconds()),
		DefaultEffectiveInterval: int64(signer.opts.DefaultEffectiveInterval.Seconds()),
		JtiGen:                   signer.opts.JtiGen.String(),
	}
}

func (signer *Signer) signany(claims jwt.MapClaims, opts ...signoptions.SignOption) (*jwt_pb.Token, error) {
	defaultopt := signoptions.DefaultSignOptions
	for _, opt := range opts {
		opt.Apply(&defaultopt)
	}
	// 构造iss
	iss := ""
	result := jwt_pb.Token{}
	if signer.opts.Iss != "" {
		iss = signer.opts.Iss
	}
	claims["iss"] = iss

	// 构造iat
	iat := time.Now().Unix()
	claims["iat"] = iat
	// 构造jti
	var jti string
	if defaultopt.Jti != "" {
		jti = defaultopt.Jti
		claims["jti"] = jti
	} else {
		if signer.opts.JtiGen != nil {
			_jti, err := signer.opts.JtiGen.Next()
			if err == nil {
				jti = _jti
				claims["jti"] = jti
			} else {
				return nil, err
			}
		}
	}

	sub := ""
	if defaultopt.Sub != "" {
		sub = defaultopt.Sub
		claims["sub"] = sub
	}
	var aud []string = nil
	if defaultopt.Aud != nil {
		aud = defaultopt.Aud
		claims["aud"] = aud
	}

	var nbr int64 = 0
	if defaultopt.Nbf != 0 {
		nbr = defaultopt.Nbf
	} else {
		if signer.opts.DefaultEffectiveInterval > 0 {
			nbr = time.Now().Add(signer.opts.DefaultEffectiveInterval).Unix()
		}
	}
	if defaultopt.Exp > 0 {
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
	accesstoken := jwt.NewWithClaims(signer.algo, claims)
	accesstokenb, err := accesstoken.SignedString(signer.key)
	if err != nil {
		return nil, err
	}
	result.AccessToken = accesstokenb
	// 如果设置了刷新过期,则创建伴生刷新token
	if defaultopt.RefreshExp > 0 {
		if sub == "" {
			return nil, exceptions.ErrSignWithRefreshTokenNeedSUB
		}
		refresh_claims := jwt.MapClaims{"sub": sub, "iat": iat, "exp": defaultopt.RefreshExp}
		if aud != nil {
			refresh_claims["aud"] = aud
		}
		if iss != "" {
			refresh_claims["iss"] = iss
		}
		if jti != "" {
			refresh_claims["jti"] = jti
		}
		if nbr != 0 {
			refresh_claims["nbr"] = nbr
		}
		refresh_token := jwt.NewWithClaims(signer.algo, refresh_claims)
		refresh_tokenb, err := refresh_token.SignedString(signer.key)
		if err != nil {
			return nil, err
		}
		result.RefreshToken = refresh_tokenb
	}
	return &result, nil
}

//Sign 签名一个token
//@Params payload interface{} 负载对象,需要是可以用json解析的对象
//@Params opts ...signoptions.SignOption 签名的设置项,详见signoptions模块
//@Returns *jwt_pb.Token jwt的token对象,其中AccessToken是jwt主体token,如果成功一定会有,如果设置了`WithRefreshExpAt`或者`WithRefreshTTL`则会创建一个伴生的RefreshToken用于自动刷新
func (signer *Signer) Sign(payload interface{}, opts ...signoptions.SignOption) (*jwt_pb.Token, error) {
	var payloadb []byte
	var err error
	if payload == nil {
		payloadb, err = json.Marshal(map[string]interface{}{})
	} else {
		payloadb, err = json.Marshal(payload)
	}

	if err != nil {
		return nil, err //ErrParseClaimsToJSON
	}
	payloadclaims := jwt.MapClaims{}
	err = json.Unmarshal(payloadb, &payloadclaims)
	if err != nil {
		return nil, err //ErrParseClaimsToJSON
	}
	return signer.signany(payloadclaims, opts...)
}
