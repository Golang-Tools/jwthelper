package verifyoptions

//VerifyOptions 校验函数参数
type VerifyOptions struct {
	CheckMatchSUB string   //校验token的sub是否符合这个字段填写的值
	CheckMatchAUD string   // 校验token的aud是不是包含这个字段中指定的值
	CheckMatchISS []string //校验token的签发人是否在这个字段给定的范围中
}

type VerifyOption interface {
	Apply(*VerifyOptions)
}

// func (emptyOption) apply(*VerifyOptions) {}
type funcVerifyOption struct {
	f func(*VerifyOptions)
}

func (fo *funcVerifyOption) Apply(do *VerifyOptions) {
	fo.f(do)
}

func newFuncVerifyOption(f func(*VerifyOptions)) *funcVerifyOption {
	return &funcVerifyOption{
		f: f,
	}
}

//WithSUBMustBe 校验用户是否与给定值匹配
func WithSUBMustBe(sub string) VerifyOption {
	return newFuncVerifyOption(func(o *VerifyOptions) {
		o.CheckMatchSUB = sub
	})
}

//WithAUDMusthas 校验token的aud中必须包含指定值
func WithAUDMustHas(aud string) VerifyOption {
	return newFuncVerifyOption(func(o *VerifyOptions) {
		o.CheckMatchAUD = aud
	})
}

//WithAUDMusthas 校验token的iss必须在指定范围内
func WithIssMustIn(isss ...string) VerifyOption {
	return newFuncVerifyOption(func(o *VerifyOptions) {
		o.CheckMatchISS = isss
	})
}
