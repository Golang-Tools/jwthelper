// verifyoptions 签名校验器校验方法的参数
package verifyoptions

import "github.com/Golang-Tools/optparams"

//VerifyOptions 校验函数参数
type VerifyOptions struct {
	CheckMatchSUB           string   //校验token的sub是否符合这个字段填写的值
	CheckMatchALLAUD        []string // 校验token的aud是不是包含这个字段中指定的所有值
	CheckMatchAnyAUD        []string // 校验token的aud是不是包含这个字段中指定的至少一个值
	CheckNotMatchAUD        []string // 校验token的aud是不是不包含这个字段中指定的任何一个值
	CheckMatchISS           []string //校验token的签发人是否在这个字段给定的范围中
	NotCheckRefreshTokenAUD bool     //是否校验RefreshToken中的AUD必须和对应AccessToken的一致
	NotCheckRefreshTokenJTI bool     //是否校验RefreshToken中的JTI必须和对应AccessToken的一致
}

//WithSUBMustBe 校验用户是否与给定值匹配
func WithSUBMustBe(sub string) optparams.Option[VerifyOptions] {
	return optparams.NewFuncOption(func(o *VerifyOptions) {
		o.CheckMatchSUB = sub
	})
}

//WithAUDMustHas 校验token的aud中必须包含指定所有值
func WithAUDMustHas(auds ...string) optparams.Option[VerifyOptions] {
	return optparams.NewFuncOption(func(o *VerifyOptions) {
		o.CheckMatchALLAUD = auds
	})
}

//WithAUDMustHasAny 校验token的aud中必须包含指定值范围内的至少一个值
func WithAUDMustHasAny(auds ...string) optparams.Option[VerifyOptions] {
	return optparams.NewFuncOption(func(o *VerifyOptions) {
		o.CheckMatchAnyAUD = auds
	})
}

//WithAUDMustNotHas 校验token的aud中必须不包含指定值范围内的所有值
func WithAUDMustNotHas(auds ...string) optparams.Option[VerifyOptions] {
	return optparams.NewFuncOption(func(o *VerifyOptions) {
		o.CheckNotMatchAUD = auds
	})
}

//WithIssMustIn 校验token的iss必须在指定范围内
func WithIssMustIn(isss ...string) optparams.Option[VerifyOptions] {
	return optparams.NewFuncOption(func(o *VerifyOptions) {
		o.CheckMatchISS = isss
	})
}

//WithNotCheckRefreshTokenAUD 设置不校验RefreshToken中的AUD必须和对应AccessToken的一致
func WithNotCheckRefreshTokenAUD() optparams.Option[VerifyOptions] {
	return optparams.NewFuncOption(func(o *VerifyOptions) {
		o.NotCheckRefreshTokenAUD = true
	})
}

//WithNotCheckRefreshTokenJTI 设置不校验RefreshToken中的JTI必须和对应AccessToken的一致
func WithNotCheckRefreshTokenJTI() optparams.Option[VerifyOptions] {
	return optparams.NewFuncOption(func(o *VerifyOptions) {
		o.NotCheckRefreshTokenJTI = true
	})
}
