// 领域类型:与传输层(pb)解耦的核心类型定义。
package jwthelper

// Algo 加密算法标识,取值为标准 JOSE 算法名(如 "HS256"、"EdDSA")。
type Algo string

// 支持的加密算法。
const (
	AlgoHS256 Algo = "HS256"
	AlgoHS384 Algo = "HS384"
	AlgoHS512 Algo = "HS512"
	AlgoRS256 Algo = "RS256"
	AlgoRS384 Algo = "RS384"
	AlgoRS512 Algo = "RS512"
	AlgoES256 Algo = "ES256"
	AlgoES384 Algo = "ES384"
	AlgoES512 Algo = "ES512"
	AlgoEdDSA Algo = "EdDSA"
)

// String 返回算法名。
func (a Algo) String() string { return string(a) }

// Token jwt令牌对。
type Token struct {
	//AccessToken 访问令牌
	AccessToken string
	//RefreshToken 伴生刷新令牌,未开启时为空
	RefreshToken string
}

// SignerMeta 签名器元信息。
type SignerMeta struct {
	//Algo 签名使用的算法
	Algo Algo
	//Iss 签发人
	Iss string
	//DefaultTTL 默认令牌存在时长(秒)
	DefaultTTL int64
	//DefaultEffectiveInterval 默认令牌生效间隔(秒)
	DefaultEffectiveInterval int64
	//JtiGen jti生成器名
	JtiGen string
}

// VerifierMeta 校验器元信息。
type VerifierMeta struct {
	//Algo 校验使用的算法
	Algo Algo
	//DefaultAUD 默认校验的aud
	DefaultAUD string
	//DefaultISSRange 默认校验的iss范围
	DefaultISSRange []string
}

// JwtStatus 校验结果状态。
type JwtStatus struct {
	//Jti 令牌id
	Jti string
	//Sub 令牌主体
	Sub string
	//Iss 签发人
	Iss string
	//Aud 受众
	Aud []string
	//ExpAt 过期时间戳(Unix秒);无exp时为0
	ExpAt int64
	//TimeLeft 剩余有效秒数(ExpAt-now);无exp时为0
	TimeLeft int64
}
