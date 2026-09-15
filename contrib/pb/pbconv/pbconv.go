// 核心类型与传输层pb类型之间的转换。
// 该模块是核心jwt逻辑与pb传输层的隔离层:核心逻辑只依赖根包的领域类型,
// 传输层(pb/grpc/http)通过本模块在边界处完成转换。
package pbconv

import (
	"github.com/Golang-Tools/jwthelper/contrib/pb/jwtpb"
	jwthelper "github.com/Golang-Tools/jwthelper/v4"
	"github.com/Golang-Tools/jwthelper/v4/exceptions"
)

// AlgoToPB 核心算法名转pb枚举,未知算法返回UNKNOWN
func AlgoToPB(a jwthelper.Algo) jwtpb.EncryptionAlgorithm {
	switch a {
	case jwthelper.AlgoHS256:
		return jwtpb.EncryptionAlgorithm_HS256
	case jwthelper.AlgoHS384:
		return jwtpb.EncryptionAlgorithm_HS384
	case jwthelper.AlgoHS512:
		return jwtpb.EncryptionAlgorithm_HS512
	case jwthelper.AlgoRS256:
		return jwtpb.EncryptionAlgorithm_RS256
	case jwthelper.AlgoRS384:
		return jwtpb.EncryptionAlgorithm_RS384
	case jwthelper.AlgoRS512:
		return jwtpb.EncryptionAlgorithm_RS512
	case jwthelper.AlgoES256:
		return jwtpb.EncryptionAlgorithm_ES256
	case jwthelper.AlgoES384:
		return jwtpb.EncryptionAlgorithm_ES384
	case jwthelper.AlgoES512:
		return jwtpb.EncryptionAlgorithm_ES512
	case jwthelper.AlgoEdDSA:
		return jwtpb.EncryptionAlgorithm_EdDSA
	default:
		return jwtpb.EncryptionAlgorithm_UNKNOWN
	}
}

// AlgoFromPB pb枚举转核心算法名,UNKNOWN返回ErrAlgoType
func AlgoFromPB(a jwtpb.EncryptionAlgorithm) (jwthelper.Algo, error) {
	switch a {
	case jwtpb.EncryptionAlgorithm_HS256:
		return jwthelper.AlgoHS256, nil
	case jwtpb.EncryptionAlgorithm_HS384:
		return jwthelper.AlgoHS384, nil
	case jwtpb.EncryptionAlgorithm_HS512:
		return jwthelper.AlgoHS512, nil
	case jwtpb.EncryptionAlgorithm_RS256:
		return jwthelper.AlgoRS256, nil
	case jwtpb.EncryptionAlgorithm_RS384:
		return jwthelper.AlgoRS384, nil
	case jwtpb.EncryptionAlgorithm_RS512:
		return jwthelper.AlgoRS512, nil
	case jwtpb.EncryptionAlgorithm_ES256:
		return jwthelper.AlgoES256, nil
	case jwtpb.EncryptionAlgorithm_ES384:
		return jwthelper.AlgoES384, nil
	case jwtpb.EncryptionAlgorithm_ES512:
		return jwthelper.AlgoES512, nil
	case jwtpb.EncryptionAlgorithm_EdDSA:
		return jwthelper.AlgoEdDSA, nil
	default:
		return "", exceptions.ErrAlgoType
	}
}

// TokenToPB 核心令牌转pb令牌,nil输入返回nil
func TokenToPB(t *jwthelper.Token) *jwtpb.Token {
	if t == nil {
		return nil
	}
	return &jwtpb.Token{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
	}
}

// TokenFromPB pb令牌转核心令牌,nil输入返回空令牌(便于后续统一返回AccessTokenNotFound)
func TokenFromPB(t *jwtpb.Token) *jwthelper.Token {
	if t == nil {
		return &jwthelper.Token{}
	}
	return &jwthelper.Token{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
	}
}

// SignerMetaToPB 签名器元信息转pb,nil输入返回nil
func SignerMetaToPB(m *jwthelper.SignerMeta) *jwtpb.SignerMeta {
	if m == nil {
		return nil
	}
	return &jwtpb.SignerMeta{
		Algo:                     AlgoToPB(m.Algo),
		Iss:                      m.Iss,
		DefaultTTL:               m.DefaultTTL,
		DefaultEffectiveInterval: m.DefaultEffectiveInterval,
		JtiGen:                   m.JtiGen,
	}
}

// SignerMetaFromPB pb签名器元信息转核心,nil输入返回nil,算法无法识别时返回ErrAlgoType
func SignerMetaFromPB(m *jwtpb.SignerMeta) (*jwthelper.SignerMeta, error) {
	if m == nil {
		return nil, nil
	}
	algo, err := AlgoFromPB(m.Algo)
	if err != nil {
		return nil, err
	}
	return &jwthelper.SignerMeta{
		Algo:                     algo,
		Iss:                      m.Iss,
		DefaultTTL:               m.DefaultTTL,
		DefaultEffectiveInterval: m.DefaultEffectiveInterval,
		JtiGen:                   m.JtiGen,
	}, nil
}

// VerifierMetaToPB 校验器元信息转pb,nil输入返回nil
func VerifierMetaToPB(m *jwthelper.VerifierMeta) *jwtpb.VerifierMeta {
	if m == nil {
		return nil
	}
	return &jwtpb.VerifierMeta{
		Algo:            AlgoToPB(m.Algo),
		DefaultAUD:      m.DefaultAUD,
		DefaultISSRange: m.DefaultISSRange,
	}
}

// VerifierMetaFromPB pb校验器元信息转核心,nil输入返回nil,算法无法识别时返回ErrAlgoType
func VerifierMetaFromPB(m *jwtpb.VerifierMeta) (*jwthelper.VerifierMeta, error) {
	if m == nil {
		return nil, nil
	}
	algo, err := AlgoFromPB(m.Algo)
	if err != nil {
		return nil, err
	}
	return &jwthelper.VerifierMeta{
		Algo:            algo,
		DefaultAUD:      m.DefaultAUD,
		DefaultISSRange: m.DefaultISSRange,
	}, nil
}

// JwtStatusToPB 核心校验状态转pb,nil输入返回nil。
// 注意pb当前没有exp_at字段,ExpAt不参与传输,接收方可通过TimeLeft自行推算
func JwtStatusToPB(s *jwthelper.JwtStatus) *jwtpb.JwtStatus {
	if s == nil {
		return nil
	}
	return &jwtpb.JwtStatus{
		Jti:      s.Jti,
		Sub:      s.Sub,
		Iss:      s.Iss,
		TimeLeft: s.TimeLeft,
		Aud:      s.Aud,
	}
}

// JwtStatusFromPB pb校验状态转核心,nil输入返回nil(ExpAt置0,由调用方按需补充)
func JwtStatusFromPB(s *jwtpb.JwtStatus) *jwthelper.JwtStatus {
	if s == nil {
		return nil
	}
	return &jwthelper.JwtStatus{
		Jti:      s.Jti,
		Sub:      s.Sub,
		Iss:      s.Iss,
		TimeLeft: s.TimeLeft,
		Aud:      s.Aud,
	}
}
