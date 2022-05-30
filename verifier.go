// verifier jwt校验器
package jwthelper

import (
	"reflect"
	"regexp"

	"github.com/Golang-Tools/jwthelper/v2/exceptions"
	"github.com/Golang-Tools/jwthelper/v2/jwt_pb"
	utils "github.com/Golang-Tools/jwthelper/v2/utils"
	"github.com/Golang-Tools/jwthelper/v2/verifyoptions"
	"github.com/Golang-Tools/optparams"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/scylladb/go-set/strset"
)

type Verifier struct {
	asymmetric bool
	opts       VerifierOptions
	key        interface{}
}

// NewVerifier 创建一个签名校验器对象
func NewVerifier(opts ...optparams.Option[VerifierOptions]) (*Verifier, error) {
	s := new(Verifier)
	s.opts = DefaultVerifierOptions
	optparams.GetOption(&s.opts, opts...)
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

//Meta 获取签名器元数据
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
		Aud := strset.New()
		switch reflect.TypeOf(audi).Kind() {
		case reflect.Slice, reflect.Array:
			s := reflect.ValueOf(audi)
			for i := 0; i < s.Len(); i++ {
				va := s.Index(i).Interface().(string)
				Aud.Add(va)
			}
		case reflect.String:
			s := reflect.ValueOf(audi)
			Aud.Add(s.Interface().(string))
		}
		if opts.CheckMatchALLAUD != nil && len(opts.CheckMatchALLAUD) > 0 {
			if !Aud.Has(opts.CheckMatchALLAUD...) {
				return exceptions.ErrValidationErrorAudience
			}
		}
		if opts.CheckMatchAnyAUD != nil && len(opts.CheckMatchAnyAUD) > 0 {
			if !Aud.HasAny(opts.CheckMatchAnyAUD...) {
				return exceptions.ErrValidationErrorAudience
			}
		}
		if opts.CheckNotMatchAUD != nil && len(opts.CheckNotMatchAUD) > 0 {
			if Aud.HasAny(opts.CheckNotMatchAUD...) {
				return exceptions.ErrValidationErrorAudience
			}
		}
		jwt_status.Aud = Aud.List()
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
		jwt_status.Jti = jtii.(string)
		delete(claims, "jti")
	}
	_, ok = claims["iat"]
	if ok {
		delete(claims, "iat")
	}
	issi, ok := claims["iss"]
	if ok {
		jwt_status.Iss = issi.(string)
		delete(claims, "iss")
	}
	_, ok = claims["nbf"]
	if ok {
		delete(claims, "nbf")
	}
	subi, ok := claims["sub"]
	if ok {
		jwt_status.Sub = subi.(string)
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

//verifyAccessToken 如果只是超时一样会进入校验流程同时给payload赋值,返回第一位设置为sub
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
				access_time_left = int64(exp.(float64))
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

//checkRefreshToken 校验伴生的refreshtoken是否相符
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
			access_time_left := int64(exp.(float64))
			// RefreshToken的sub必须和主体一致
			subi, ok := claims["sub"]
			if !ok {
				return exceptions.ErrRefreshTokenSUBNotMatch
			}
			if jwt_status.Sub != subi.(string) {
				return exceptions.ErrRefreshTokenSUBNotMatch
			}
			if !opts.NotCheckRefreshTokenJTI {
				jtii, ok := claims["jti"]
				if !ok {
					return exceptions.ErrRefreshTokenJtiNotMatch
				}
				jti := jtii.(string)
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
				shareaudset := strset.New(jwt_status.Aud...)
				refreshaudset := strset.New()
				switch reflect.TypeOf(audi).Kind() {
				case reflect.Slice, reflect.Array:
					s := reflect.ValueOf(audi)
					for i := 0; i < s.Len(); i++ {
						va := s.Index(i).Interface().(string)
						refreshaudset.Add(va)
					}
				case reflect.String:
					s := reflect.ValueOf(audi)
					refreshaudset.Add(s.Interface().(string))
				}
				if !shareaudset.IsEqual(refreshaudset) {
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

/** Verify 用Verifier对象验签

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
@Returns *jwt_pb.JwtStatus jwt的状态信息,包括剩余时间,签发人,sub,aud等
@Returns error 各种验证失败的错误,注意当access_token过期但有refresh_token且refresh_token未过期时一样会报错exceptions.ErrValidationErrorExpired
*/
func (verifier *Verifier) Verify(token *jwt_pb.Token, payload interface{}, opts ...verifyoptions.VerifyOption) (*jwt_pb.JwtStatus, error) {
	defaultopt := verifyoptions.VerifyOptions{}
	if verifier.opts.DefaultAUD != "" {
		defaultopt.CheckMatchALLAUD = []string{verifier.opts.DefaultAUD}
	}
	if verifier.opts.DefaultISSRange != nil && len(verifier.opts.DefaultISSRange) > 0 {
		defaultopt.CheckMatchISS = verifier.opts.DefaultISSRange
	}
	for _, opt := range opts {
		opt.Apply(&defaultopt)
	}
	jwt_status := jwt_pb.JwtStatus{}
	if token.AccessToken == "" {
		return nil, exceptions.ErrAccessTokenNotFound
	}
	var accesstokenData string
	refreshtokenData := ""
	if verifier.asymmetric {
		accesstokenb := []byte(token.AccessToken)
		accesstokenDatab := regexp.MustCompile(`\s*$`).ReplaceAll(accesstokenb, []byte{})
		accesstokenData = string(accesstokenDatab)
		if token.RefreshToken != "" {
			refreshtokenb := []byte(token.RefreshToken)
			refreshtokenDatab := regexp.MustCompile(`\s*$`).ReplaceAll(refreshtokenb, []byte{})
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
