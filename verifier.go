// verifier jwt校验器
package jwthelper

import (
	"reflect"
	"regexp"
	"time"

	"github.com/Golang-Tools/jwthelper/exceptions"
	"github.com/Golang-Tools/jwthelper/jwt_pb"
	utils "github.com/Golang-Tools/jwthelper/utils"
	"github.com/Golang-Tools/jwthelper/verifyoptions"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/scylladb/go-set/strset"
)

type Verifier struct {
	asymmetric bool
	opts       VerifierOptions
	key        interface{}
}

// NewVerifier 创建一个签名校验器对象
func NewVerifier(opts ...VerifierOption) (*Verifier, error) {
	s := new(Verifier)
	s.opts = DefaultVerifierOptions
	for _, opt := range opts {
		opt.Apply(&s.opts)
	}
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
		} else {
			return nil, exceptions.ErrUnsupportAlgoType
		}
	} else {
		s.key = s.opts.Key
	}
	return s, nil
}

//Meta 获取签名器元数据
func (verifier *Verifier) Meta() *jwt_pb.VerifierMeta {
	return &jwt_pb.VerifierMeta{
		Algo:            verifier.opts.Algo,
		DefaultAUD:      verifier.opts.DefaultAUD,
		DefaultISSRange: verifier.opts.DefaultISSRange,
	}
}

//accessTokenShare access_token共享给refresh_token的信息
type accessTokenShare struct {
	Sub string
	Iss string
	Aud []string
}

// checkClaims 校验claims,并提取出负载和sub
func checkClaims(claims jwt.MapClaims, payload interface{}, opts *verifyoptions.VerifyOptions) (*accessTokenShare, error) {
	share := accessTokenShare{}

	if opts.CheckMatchSUB != "" {
		if claims["sub"] != opts.CheckMatchSUB {
			return nil, exceptions.ErrValidationErrorSubject
		}
	}
	if opts.CheckMatchAUD != "" {
		if !claims.VerifyAudience(opts.CheckMatchAUD, true) {
			return nil, exceptions.ErrValidationErrorAudience
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
			return nil, exceptions.ErrValidationErrorIssuer
		}
	}
	_, ok := claims["exp"]
	if ok {
		delete(claims, "exp")
	}
	audi, ok := claims["aud"]
	if ok {
		share.Aud = []string{}
		switch reflect.TypeOf(audi).Kind() {
		case reflect.Slice, reflect.Array:
			s := reflect.ValueOf(audi)
			for i := 0; i < s.Len(); i++ {
				share.Aud = append(share.Aud, s.Index(i).String())
			}
		case reflect.String:
			s := reflect.ValueOf(audi)
			share.Aud = append(share.Aud, s.String())
		}
		delete(claims, "aud")
	}
	_, ok = claims["jti"]
	if ok {
		delete(claims, "jti")
	}
	_, ok = claims["iat"]
	if ok {
		delete(claims, "iat")
	}
	issi, ok := claims["iss"]
	if ok {
		share.Iss = issi.(string)
		delete(claims, "iss")
	}
	_, ok = claims["nbf"]
	if ok {
		delete(claims, "nbf")
	}
	subi, ok := claims["sub"]
	if ok {
		share.Sub = subi.(string)
		delete(claims, "sub")
	}
	claimsb, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(claimsb, payload)
	if err != nil {
		return nil, err
	}
	return &share, nil
}

//verifyAccessToken 如果只是超时一样会进入校验流程同时给payload赋值,返回第一位设置为sub
func (verifier *Verifier) verifyAccessToken(accesstokenData string, payload interface{}, opts *verifyoptions.VerifyOptions) (*accessTokenShare, time.Duration, error) {
	var access_time_left time.Duration
	tok, err := jwt.Parse(
		accesstokenData,
		func(t *jwt.Token) (interface{}, error) {
			if t.Method.Alg() != verifier.opts.Algo.String() {
				return nil, exceptions.ErrAlgoTypeNotMatch
			}
			return verifier.key, nil
		})
	if tok.Valid {
		claims, ok := tok.Claims.(jwt.MapClaims)
		if ok {
			exp, ok := claims["exp"]
			if ok {
				access_time_left = time.Until(time.Unix(int64(exp.(float64)), 0))
			}
			sub, err := checkClaims(claims, payload, opts)
			if err != nil {
				return nil, 0, err
			}
			return sub, access_time_left, nil
		} else {
			return nil, 0, exceptions.ErrValidationErrorClaimsInvalid
		}
	} else {
		ve, ok := err.(*jwt.ValidationError)
		if ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return nil, 0, exceptions.ErrValidationErrorMalformed
			} else if ve.Errors&jwt.ValidationErrorUnverifiable != 0 {
				return nil, 0, exceptions.ErrValidationErrorUnverifiable
			} else if ve.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
				return nil, 0, exceptions.ErrValidationErrorSignatureInvalid
			} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
				//超时错误处理
				claims, ok := tok.Claims.(jwt.MapClaims)
				if ok {
					sub, err := checkClaims(claims, payload, opts)
					if err != nil {
						return nil, 0, err
					}
					return sub, 0, exceptions.ErrValidationErrorExpired
				}
				return nil, 0, exceptions.ErrValidationErrorExpired
			} else if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
				return nil, 0, exceptions.ErrValidationErrorNotValidYet
			} else {
				return nil, 0, exceptions.ErrValidationErrorCanNotHandle
			}
		} else {
			return nil, 0, exceptions.ErrValidationErrorUnknown
		}
	}
}

//checkRefreshToken 校验伴生的refreshtoken是否相符
func (verifier *Verifier) checkRefreshToken(refreshtokenData string, share *accessTokenShare, opts *verifyoptions.VerifyOptions) (time.Duration, error) {
	tok, err := jwt.Parse(
		refreshtokenData,
		func(t *jwt.Token) (interface{}, error) {
			if t.Method.Alg() != verifier.opts.Algo.String() {
				return nil, exceptions.ErrAlgoTypeNotMatch
			}
			return verifier.key, nil
		})
	if tok.Valid {
		claims, ok := tok.Claims.(jwt.MapClaims)

		if ok {
			exp, ok := claims["exp"]
			if !ok {
				return 0, exceptions.ErrRefreshTokenNotHaveEXP
			}
			access_time_left := time.Until(time.Unix(int64(exp.(float64)), 0))
			// 校验sub
			subi, ok := claims["sub"]
			if !ok {
				return 0, exceptions.ErrRefreshTokenSUBNotMatch
			}
			if share.Sub != subi.(string) {
				return 0, exceptions.ErrRefreshTokenSUBNotMatch
			}
			//校验aud
			if share.Aud != nil && len(share.Aud) > 0 {
				audi, ok := claims["aud"]
				if !ok {
					return 0, exceptions.ErrRefreshTokenAudNotMatch
				} else {
					shareaudset := strset.New(share.Aud...)
					refreshaudset := strset.New()
					switch reflect.TypeOf(audi).Kind() {
					case reflect.Slice, reflect.Array:
						s := reflect.ValueOf(audi)
						for i := 0; i < s.Len(); i++ {
							refreshaudset.Add(s.Index(i).String())
						}
					case reflect.String:
						s := reflect.ValueOf(audi)
						refreshaudset.Add(s.String())
					}
					if !shareaudset.IsEqual(refreshaudset) {
						return 0, exceptions.ErrRefreshTokenAudNotMatch
					}
				}
			}
			//校验iss
			if opts.CheckMatchISS != nil && len(opts.CheckMatchISS) > 0 {
				find := false
				for _, iss := range opts.CheckMatchISS {
					if claims.VerifyIssuer(iss, true) {
						find = true
						break
					}
				}
				if !find {
					return 0, exceptions.ErrRefreshTokenIssNotInRange
				}
			}
			return access_time_left, nil
		} else {
			return 0, exceptions.ErrRefreshTokenParseError
		}
	} else {
		if err != nil {
			return 0, err
		} else {
			return 0, exceptions.ErrRefreshTokenValidationError
		}
	}
}

// Verify 用Verifier对象验签
//@Params token jwt.Token 待校验的token
//@Params payload interface{} 校验出结果的用户负载写入的内容,注意只能是指针
//@Params opts ...verifyoptions.VerifyOption
//@Returns time.Duration 验证成功返回token的剩余时间,如果为0则表示token没有设置过期,如果token有refresh_token则时间为refresh_token的剩余时间,否则是access_token的剩余时间
//@Returns error 各种验证失败的错误
func (verifier *Verifier) Verify(token *jwt_pb.Token, payload interface{}, opts ...verifyoptions.VerifyOption) (time.Duration, error) {
	defaultopt := verifyoptions.VerifyOptions{
		CheckMatchAUD: verifier.opts.DefaultAUD,
		CheckMatchISS: verifier.opts.DefaultISSRange,
	}
	for _, opt := range opts {
		opt.Apply(&defaultopt)
	}
	if token.AccessToken == "" {
		return 0, exceptions.ErrAccessTokenNotFound
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

	sub, timeleft, err := verifier.verifyAccessToken(accesstokenData, payload, &defaultopt)
	if err == nil {
		if refreshtokenData == "" {
			return timeleft, nil
		} else {
			timeleft, err := verifier.checkRefreshToken(refreshtokenData, sub, &defaultopt)
			if err != nil {
				return 0, err
			}
			return timeleft, nil
		}
	} else {
		if err == exceptions.ErrValidationErrorExpired {
			if refreshtokenData == "" {
				return 0, err
			}
			timeleft, err := verifier.checkRefreshToken(refreshtokenData, sub, &defaultopt)
			if err != nil {
				return 0, err
			}
			return timeleft, nil
		} else {
			return 0, err
		}
	}
}
