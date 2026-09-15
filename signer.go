// signer jwt的签名器

package jwthelper

import (
	"context"
	"time"

	"github.com/Golang-Tools/jwthelper/v4/exceptions"
	"github.com/Golang-Tools/jwthelper/v4/signoptions"
	"github.com/Golang-Tools/optparams"
	jwt "github.com/golang-jwt/jwt/v4"
)

type Signer struct {
	algo        jwt.SigningMethod
	keyProvider SignerKeyProvider
	opts        SignerOptions
}

// NewSigner 创建一个签名器对象
func NewSigner(opts ...optparams.Option[SignerOptions]) (*Signer, error) {
	s := new(Signer)
	s.opts = *optparams.GetOption(&defaultSignerOptions, opts...)
	if s.opts.err != nil {
		return nil, s.opts.err
	}
	if !IsAsymmetric(s.opts.Algo) && !IsSymmetric(s.opts.Algo) {
		return nil, exceptions.ErrUnsupportAlgoType
	}
	algo := jwt.GetSigningMethod(s.opts.Algo.String())
	if algo == nil {
		return nil, exceptions.ErrUnsupportAlgoType
	}
	s.algo = algo
	if s.opts.KeyProvider != nil {
		s.keyProvider = s.opts.KeyProvider
	} else {
		keyProvider, err := NewSignerKey(s.opts.Key, s.opts.Algo)
		if err != nil {
			return nil, err
		}
		s.keyProvider = keyProvider
	}
	return s, nil
}

// Meta 获取签名器元数据
func (signer *Signer) Meta(ctx context.Context) (*SignerMeta, error) {
	jtiGen := ""
	if signer.opts.JtiGen != nil {
		jtiGen = signer.opts.JtiGen.String()
	}
	return &SignerMeta{
		Algo:                     signer.opts.Algo,
		Iss:                      signer.opts.Iss,
		DefaultTTL:               int64(signer.opts.DefaultTTL.Seconds()),
		DefaultEffectiveInterval: int64(signer.opts.DefaultEffectiveInterval.Seconds()),
		JtiGen:                   jtiGen,
	}, nil
}

func (signer *Signer) signany(ctx context.Context, claims jwt.MapClaims, opts ...optparams.Option[signoptions.SignOptions]) (*Token, error) {
	defaultopt := optparams.GetOption(&signoptions.DefaultSignOptions, opts...)
	// 构造iss
	iss := ""
	result := Token{}
	if signer.opts.Iss != "" {
		iss = signer.opts.Iss
	}
	claims["iss"] = iss

	// 构造iat
	iat := nowUnix(signer.opts.Clock)
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

	var nbf int64 = 0
	if defaultopt.Nbf != 0 {
		nbf = defaultopt.Nbf
	} else {
		if signer.opts.DefaultEffectiveInterval > 0 {
			nbf = time.Unix(iat, 0).Add(signer.opts.DefaultEffectiveInterval).Unix()
		}
	}
	if defaultopt.Exp > 0 {
		claims["exp"] = defaultopt.Exp
	} else {
		if signer.opts.DefaultTTL > 0 {
			if nbf > 0 {
				claims["exp"] = time.Unix(nbf, 0).Add(signer.opts.DefaultTTL).Unix()
			} else {
				claims["exp"] = time.Unix(iat, 0).Add(signer.opts.DefaultTTL).Unix()
			}
		}
	}
	if nbf > 0 {
		claims["nbf"] = nbf
	}
	signingKey, err := signer.keyProvider.SigningKey(ctx, signer.opts.Algo)
	if err != nil {
		return nil, err
	}
	accesstoken := jwt.NewWithClaims(signer.algo, claims)
	accesstokenb, err := accesstoken.SignedString(signingKey)
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
		if nbf != 0 {
			refresh_claims["nbf"] = nbf
		}
		refresh_token := jwt.NewWithClaims(signer.algo, refresh_claims)
		refresh_tokenb, err := refresh_token.SignedString(signingKey)
		if err != nil {
			return nil, err
		}
		result.RefreshToken = refresh_tokenb
	}
	return &result, nil
}

// Sign 签名一个token
// @Params ctx context.Context 上下文
// @Params payload interface{} 负载对象,需要是可以用codec解析的对象
// @Params opts ...optparams.Option[signoptions.SignOptions] 签名的设置项,详见signoptions模块
// @Returns *Token jwt的token对象,其中AccessToken是jwt主体token,如果成功一定会有,如果设置了`WithRefreshExpAt`或者`WithRefreshTTL`则会创建一个伴生的RefreshToken用于自动刷新
func (signer *Signer) Sign(ctx context.Context, payload interface{}, opts ...optparams.Option[signoptions.SignOptions]) (*Token, error) {
	codec := codecOrStd(signer.opts.Codec)
	var payloadb []byte
	var err error
	if payload == nil {
		payloadb, err = codec.Marshal(map[string]interface{}{})
	} else {
		payloadb, err = codec.Marshal(payload)
	}

	if err != nil {
		return nil, err //ErrParseClaimsToJSON
	}
	payloadclaims := jwt.MapClaims{}
	err = codec.Unmarshal(payloadb, &payloadclaims)
	if err != nil {
		return nil, err //ErrParseClaimsToJSON
	}
	return signer.signany(ctx, payloadclaims, opts...)
}
