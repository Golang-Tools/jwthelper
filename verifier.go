// verifier jwt校验器
package jwthelper

import (
	"encoding/json"
	"regexp"

	"github.com/Golang-Tools/jwthelper/v3/exceptions"
	"github.com/Golang-Tools/jwthelper/v3/jwt_pb"
	utils "github.com/Golang-Tools/jwthelper/v3/utils"
	"github.com/Golang-Tools/jwthelper/v3/verifyoptions"
	"github.com/Golang-Tools/optparams"
	mapset "github.com/deckarep/golang-set/v2"
	jwt "github.com/golang-jwt/jwt/v4"
)

type Verifier struct {
	asymmetric bool
	opts       VerifierOptions
	key        interface{}
}

// trailingSpacesRe 匹配 token 字符串末尾的空白字符,用于清理 PEM 解析时可能混入的尾随空白。
var trailingSpacesRe = regexp.MustCompile(`\s*$`)

// NewVerifier 创建一个签名校验器对象
func NewVerifier(opts ...optparams.Option[VerifierOptions]) (*Verifier, error) {
	s := new(Verifier)
	s.opts = DefaultVerifierOptions
	s.opts = *optparams.GetOption(&s.opts, opts...)
	if !utils.IsAsymmetric(s.opts.Algo) && !utils.IsSymmetric(s.opts.Algo) {
		return nil, exceptions.ErrUnsupportAlgoType
	}
	if utils.IsAsymmetric(s.opts.Algo) {
		s.asymmetric = true
		if utils.IsEs(s.opts.Algo) {
			key, err := jwt.ParseECPublicKeyFromPEM(s.opts.Key)
			if err != nil {
				return nil, err
			}
			s.key = key
		} else if utils.IsRs(s.opts.Algo) {
			key, err := jwt.ParseRSAPublicKeyFromPEM(s.opts.Key)
			if err != nil {
				return nil, err
			}
			s.key = key
		} else if utils.IsEdDSA(s.opts.Algo) {
			key, err := jwt.ParseEdPublicKeyFromPEM(s.opts.Key)
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

// Meta 获取签名器元数据
func (verifier *Verifier) Meta() (*jwt_pb.VerifierMeta, error) {
	return &jwt_pb.VerifierMeta{
		Algo:            verifier.opts.Algo,
		DefaultAUD:      verifier.opts.DefaultAUD,
		DefaultISSRange: verifier.opts.DefaultISSRange,
	}, nil
}

// checkClaims 校验claims,并提取出负载和sub
// 校验顺序是sub>aud>iss
func checkClaims(claims jwt.MapClaims, payload interface{}, jwt_status *jwt_pb.JwtStatus, opts *verifyoptions.VerifyOptions) error {
	if opts.CheckMatchSUB != "" {
		if claims["sub"] != opts.CheckMatchSUB {
			return exceptions.ErrValidationErrorSubject
		}
	}
	if opts.CheckMatchISS != nil && len(opts.CheckMatchISS) > 0 {
		find := false
		for _, iss := range opts.CheckMatchISS {
			if claims.VerifyIssuer(iss, true) {
				find = true
				break
			}
		}
		if !find {
			return exceptions.ErrValidationErrorIssuer
		}
	}
	_, ok := claims["exp"]
	if ok {
		delete(claims, "exp")
	}
	audi, ok := claims["aud"]
	if ok {
		Aud := mapset.NewSet[string]()
		valid := true
		switch v := audi.(type) {
		case string:
			Aud.Add(v)
		case []interface{}:
			for _, item := range v {
				va, ok := item.(string)
				if !ok {
					valid = false
					break
				}
				Aud.Add(va)
			}
		case []string:
			Aud.Append(v...)
		default:
			valid = false
		}
		if !valid {
			return exceptions.ErrValidationErrorMalformed
		}
		if opts.CheckMatchALLAUD != nil && len(opts.CheckMatchALLAUD) > 0 {
			if !Aud.Contains(opts.CheckMatchALLAUD...) {
				return exceptions.ErrValidationErrorAudience
			}
		}
		if opts.CheckMatchAnyAUD != nil && len(opts.CheckMatchAnyAUD) > 0 {
			if Aud.Intersect(mapset.NewSet(opts.CheckMatchAnyAUD...)).Cardinality() <= 0 {
				return exceptions.ErrValidationErrorAudience
			}
		}
		if opts.CheckNotMatchAUD != nil && len(opts.CheckNotMatchAUD) > 0 {
			if Aud.Intersect(mapset.NewSet(opts.CheckNotMatchAUD...)).Cardinality() > 0 {
				return exceptions.ErrValidationErrorAudience
			}
		}
		jwt_status.Aud = Aud.ToSlice()
		delete(claims, "aud")
	} else {
		if opts.CheckMatchALLAUD != nil && len(opts.CheckMatchALLAUD) > 0 {
			return exceptions.ErrValidationErrorAudience
		}
		if opts.CheckMatchAnyAUD != nil && len(opts.CheckMatchAnyAUD) > 0 {
			return exceptions.ErrValidationErrorAudience
		}
		if opts.CheckNotMatchAUD != nil && len(opts.CheckNotMatchAUD) > 0 {
			return exceptions.ErrValidationErrorAudience
		}
	}
	jtii, ok := claims["jti"]
	if ok {
		jti, ok := jtii.(string)
		if !ok {
			return exceptions.ErrValidationErrorMalformed
		}
		jwt_status.Jti = jti
		delete(claims, "jti")
	}
	_, ok = claims["iat"]
	if ok {
		delete(claims, "iat")
	}
	issi, ok := claims["iss"]
	if ok {
		iss, ok := issi.(string)
		if !ok {
			return exceptions.ErrValidationErrorMalformed
		}
		jwt_status.Iss = iss
		delete(claims, "iss")
	}
	_, ok = claims["nbf"]
	if ok {
		delete(claims, "nbf")
	}
	subi, ok := claims["sub"]
	if ok {
		sub, ok := subi.(string)
		if !ok {
			return exceptions.ErrValidationErrorMalformed
		}
		jwt_status.Sub = sub
		delete(claims, "sub")
	}
	claimsb, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	err = json.Unmarshal(claimsb, payload)
	if err != nil {
		return err
	}
	return nil
}

// verifyAccessToken 如果只是超时一样会进入校验流程同时给payload赋值,返回第一位设置为sub
func (verifier *Verifier) verifyAccessToken(accesstokenData string, payload interface{}, jwt_status *jwt_pb.JwtStatus, opts *verifyoptions.VerifyOptions) error {
	var access_time_left int64
	tok, err := jwt.Parse(
		accesstokenData,
		func(t *jwt.Token) (interface{}, error) {
			if t.Method.Alg() != verifier.opts.Algo.String() {
				return nil, exceptions.ErrAlgoTypeNotMatch
			}
			return verifier.key, nil
		})
	if tok != nil && tok.Valid {
		claims, ok := tok.Claims.(jwt.MapClaims)
		if ok {
			exp, ok := claims["exp"]
			if ok {
				f, ok := exp.(float64)
				if !ok {
					return exceptions.ErrValidationErrorMalformed
				}
				access_time_left = int64(f)
			}
			err := checkClaims(claims, payload, jwt_status, opts)
			if err != nil {
				return err
			}
			jwt_status.TimeLeft = access_time_left
			return nil
		} else {
			return exceptions.ErrValidationErrorClaimsInvalid
		}
	} else {
		ve, ok := err.(*jwt.ValidationError)
		if ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return exceptions.ErrValidationErrorMalformed
			} else if ve.Errors&jwt.ValidationErrorUnverifiable != 0 {
				return exceptions.ErrValidationErrorUnverifiable
			} else if ve.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
				return exceptions.ErrValidationErrorSignatureInvalid
			} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
				//超时错误处理
				claims, ok := tok.Claims.(jwt.MapClaims)
				if ok {
					err := checkClaims(claims, payload, jwt_status, opts)
					if err != nil {
						return err
					}
					return exceptions.ErrValidationErrorExpired
				}
				return exceptions.ErrValidationErrorClaimsInvalid
			} else if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
				return exceptions.ErrValidationErrorNotValidYet
			} else {
				return exceptions.ErrValidationErrorCanNotHandle
			}
		} else {
			return exceptions.ErrValidationErrorUnknown
		}
	}
}

// checkRefreshToken 校验伴生的refreshtoken是否相符
func (verifier *Verifier) checkRefreshToken(refreshtokenData string, jwt_status *jwt_pb.JwtStatus, opts *verifyoptions.VerifyOptions) error {
	tok, err := jwt.Parse(
		refreshtokenData,
		func(t *jwt.Token) (interface{}, error) {
			if t.Method.Alg() != verifier.opts.Algo.String() {
				return nil, exceptions.ErrAlgoTypeNotMatch
			}
			return verifier.key, nil
		})
	if tok != nil && tok.Valid {
		claims, ok := tok.Claims.(jwt.MapClaims)
		if ok {
			// RefreshToken必须包含exp
			exp, ok := claims["exp"]
			if !ok {
				return exceptions.ErrRefreshTokenNotHaveEXP
			}
			f, ok := exp.(float64)
			if !ok {
				return exceptions.ErrRefreshTokenValidationError
			}
			access_time_left := int64(f)
			// RefreshToken的sub必须和主体一致
			subi, ok := claims["sub"]
			if !ok {
				return exceptions.ErrRefreshTokenSUBNotMatch
			}
			sub, ok := subi.(string)
			if !ok {
				return exceptions.ErrRefreshTokenSUBNotMatch
			}
			if jwt_status.Sub != sub {
				return exceptions.ErrRefreshTokenSUBNotMatch
			}
			if !opts.NotCheckRefreshTokenJTI {
				jtii, ok := claims["jti"]
				if !ok {
					return exceptions.ErrRefreshTokenJtiNotMatch
				}
				jti, ok := jtii.(string)
				if !ok {
					return exceptions.ErrRefreshTokenJtiNotMatch
				}
				if jwt_status.Jti == "" || jti == "" || jwt_status.Jti != jti {
					return exceptions.ErrRefreshTokenJtiNotMatch
				}
			}
			//校验aud,可选
			if !opts.NotCheckRefreshTokenAUD && jwt_status.Aud != nil && len(jwt_status.Aud) > 0 {
				audi, ok := claims["aud"]
				if !ok {
					return exceptions.ErrRefreshTokenAudNotMatch
				}
				shareaudset := mapset.NewSet(jwt_status.Aud...)
				refreshaudset := mapset.NewSet[string]()
				valid := true
				switch v := audi.(type) {
				case string:
					refreshaudset.Add(v)
				case []interface{}:
					for _, item := range v {
						va, ok := item.(string)
						if !ok {
							valid = false
							break
						}
						refreshaudset.Add(va)
					}
				case []string:
					refreshaudset.Append(v...)
				default:
					valid = false
				}
				if !valid {
					return exceptions.ErrRefreshTokenAudNotMatch
				}
				if !shareaudset.Equal(refreshaudset) {
					return exceptions.ErrRefreshTokenAudNotMatch
				}
			}
			//校验iss,可选
			if opts.CheckMatchISS != nil && len(opts.CheckMatchISS) > 0 {
				find := false
				for _, iss := range opts.CheckMatchISS {
					if claims.VerifyIssuer(iss, true) {
						find = true
						break
					}
				}
				if !find {
					return exceptions.ErrRefreshTokenIssNotInRange
				}
			}
			jwt_status.TimeLeft = access_time_left
			return nil
		} else {
			return exceptions.ErrRefreshTokenParseError
		}
	} else {
		if err != nil {
			return err
		} else {
			return exceptions.ErrRefreshTokenValidationError
		}
	}
}

/*
* Verify 用Verifier对象验签

payload在有access且可以解析的情况下都会被解析出来
只有在access_token校验通过或者access_token超时但有refresh_token且refresh_token校验通过时才会有jwt_pb.JwtStatus的结果.

当access_token超时但有refresh_token且refresh_token校验通过时err为`exceptions.ErrValidationErrorExpired`

注意`refresh_token`的校验项包括

+ 是否可以解析为json
+ 是否包含`exp`字段
+ `sub`字段是否存在
+ `sub`字段是否和access_token中的一致
+ 当不指定`WithNotCheckRefreshTokenJTI`时`jti`字段必须和access_token中的一致
+ 当不指定`WithNotCheckRefreshTokenAUD`且access_token中有`aud`时则校验是否一致
+ 当指定`WithIssMustIn`选项时校验`iss`是否在指定范围

@Params token jwt.Token 待校验的token
@Params payload interface{} 校验出结果的用户负载写入的内容,注意只能是指针
@Params opts ...verifyoptions.VerifyOption
@Returns *jwt_pb.JwtStatus jwt的状态信息,包括过期时间戳(TimeLeft,Unix 秒,无 exp 时为 0),签发人,sub,aud等
@Returns error 各种验证失败的错误,注意当access_token过期但有refresh_token且refresh_token未过期时一样会报错exceptions.ErrValidationErrorExpired
*/
func (verifier *Verifier) Verify(token *jwt_pb.Token, payload interface{}, opts ...optparams.Option[verifyoptions.VerifyOptions]) (*jwt_pb.JwtStatus, error) {
	defaultopt := verifyoptions.VerifyOptions{}
	if verifier.opts.DefaultAUD != "" {
		defaultopt.CheckMatchALLAUD = []string{verifier.opts.DefaultAUD}
	}
	if verifier.opts.DefaultISSRange != nil && len(verifier.opts.DefaultISSRange) > 0 {
		defaultopt.CheckMatchISS = verifier.opts.DefaultISSRange
	}
	defaultopt = *optparams.GetOption(&defaultopt, opts...)
	jwt_status := jwt_pb.JwtStatus{}
	if token.AccessToken == "" {
		return nil, exceptions.ErrAccessTokenNotFound
	}
	var accesstokenData string
	refreshtokenData := ""
	if verifier.asymmetric {
		accesstokenb := []byte(token.AccessToken)
		accesstokenDatab := trailingSpacesRe.ReplaceAll(accesstokenb, []byte{})
		accesstokenData = string(accesstokenDatab)
		if token.RefreshToken != "" {
			refreshtokenb := []byte(token.RefreshToken)
			refreshtokenDatab := trailingSpacesRe.ReplaceAll(refreshtokenb, []byte{})
			refreshtokenData = string(refreshtokenDatab)
		}
	} else {
		accesstokenData = token.AccessToken
		if token.RefreshToken != "" {
			refreshtokenData = token.RefreshToken
		}
	}

	err := verifier.verifyAccessToken(accesstokenData, payload, &jwt_status, &defaultopt)
	if err == nil {
		if refreshtokenData == "" {
			return &jwt_status, nil
		} else {
			err := verifier.checkRefreshToken(refreshtokenData, &jwt_status, &defaultopt)
			if err != nil {
				return nil, err
			}
			return &jwt_status, nil
		}
	} else {
		if err == exceptions.ErrValidationErrorExpired {
			if refreshtokenData == "" {
				return nil, err
			}
			err := verifier.checkRefreshToken(refreshtokenData, &jwt_status, &defaultopt)
			if err != nil {
				return nil, err
			}
			return &jwt_status, exceptions.ErrValidationErrorExpired
		} else {
			return nil, err
		}
	}
}
