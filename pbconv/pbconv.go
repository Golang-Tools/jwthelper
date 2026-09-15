// 核心类型与传输层pb类型之间的转换。
// 该模块是核心jwt逻辑与pb传输层的隔离层:核心逻辑只依赖根包的领域类型,
// 传输层(pb/grpc/http)通过本模块在边界处完成转换。
package pbconv

import (
	jwthelper "github.com/Golang-Tools/jwthelper/v4"
	"github.com/Golang-Tools/jwthelper/v4/exceptions"
	"github.com/Golang-Tools/jwthelper/v4/jwt_pb"
)

// AlgoToPB 核心算法名转pb枚举,未知算法返回UNKNOWN
func AlgoToPB(a jwthelper.Algo) jwt_pb.EncryptionAlgorithm {
	switch a {
	case jwthelper.AlgoHS256:
		return jwt_pb.EncryptionAlgorithm_HS256
	case jwthelper.AlgoHS384:
		return jwt_pb.EncryptionAlgorithm_HS384
	case jwthelper.AlgoHS512:
		return jwt_pb.EncryptionAlgorithm_HS512
	case jwthelper.AlgoRS256:
		return jwt_pb.EncryptionAlgorithm_RS256
	case jwthelper.AlgoRS384:
		return jwt_pb.EncryptionAlgorithm_RS384
	case jwthelper.AlgoRS512:
		return jwt_pb.EncryptionAlgorithm_RS512
	case jwthelper.AlgoES256:
		return jwt_pb.EncryptionAlgorithm_ES256
	case jwthelper.AlgoES384:
		return jwt_pb.EncryptionAlgorithm_ES384
	case jwthelper.AlgoES512:
		return jwt_pb.EncryptionAlgorithm_ES512
	case jwthelper.AlgoEdDSA:
		return jwt_pb.EncryptionAlgorithm_EdDSA
	default:
		return jwt_pb.EncryptionAlgorithm_UNKNOWN
	}
}

// AlgoFromPB pb枚举转核心算法名,UNKNOWN返回ErrAlgoType
func AlgoFromPB(a jwt_pb.EncryptionAlgorithm) (jwthelper.Algo, error) {
	switch a {
	case jwt_pb.EncryptionAlgorithm_HS256:
		return jwthelper.AlgoHS256, nil
	case jwt_pb.EncryptionAlgorithm_HS384:
		return jwthelper.AlgoHS384, nil
	case jwt_pb.EncryptionAlgorithm_HS512:
		return jwthelper.AlgoHS512, nil
	case jwt_pb.EncryptionAlgorithm_RS256:
		return jwthelper.AlgoRS256, nil
	case jwt_pb.EncryptionAlgorithm_RS384:
		return jwthelper.AlgoRS384, nil
	case jwt_pb.EncryptionAlgorithm_RS512:
		return jwthelper.AlgoRS512, nil
	case jwt_pb.EncryptionAlgorithm_ES256:
		return jwthelper.AlgoES256, nil
	case jwt_pb.EncryptionAlgorithm_ES384:
		return jwthelper.AlgoES384, nil
	case jwt_pb.EncryptionAlgorithm_ES512:
		return jwthelper.AlgoES512, nil
	case jwt_pb.EncryptionAlgorithm_EdDSA:
		return jwthelper.AlgoEdDSA, nil
	default:
		return "", exceptions.ErrAlgoType
	}
}

// TokenToPB 核心令牌转pb令牌,nil输入返回nil
func TokenToPB(t *jwthelper.Token) *jwt_pb.Token {
	if t == nil {
		return nil
	}
	return &jwt_pb.Token{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
	}
}

// TokenFromPB pb令牌转核心令牌,nil输入返回空令牌(便于后续统一返回AccessTokenNotFound)
func TokenFromPB(t *jwt_pb.Token) *jwthelper.Token {
	if t == nil {
		return &jwthelper.Token{}
	}
	return &jwthelper.Token{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
	}
}

// SignerMetaToPB 签名器元信息转pb,nil输入返回nil
func SignerMetaToPB(m *jwthelper.SignerMeta) *jwt_pb.SignerMeta {
	if m == nil {
		return nil
	}
	return &jwt_pb.SignerMeta{
		Algo:                     AlgoToPB(m.Algo),
		Iss:                      m.Iss,
		DefaultTTL:               m.DefaultTTL,
		DefaultEffectiveInterval: m.DefaultEffectiveInterval,
		JtiGen:                   m.JtiGen,
	}
}

// SignerMetaFromPB pb签名器元信息转核心,nil输入返回nil,算法无法识别时返回ErrAlgoType
func SignerMetaFromPB(m *jwt_pb.SignerMeta) (*jwthelper.SignerMeta, error) {
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
func VerifierMetaToPB(m *jwthelper.VerifierMeta) *jwt_pb.VerifierMeta {
	if m == nil {
		return nil
	}
	return &jwt_pb.VerifierMeta{
		Algo:            AlgoToPB(m.Algo),
		DefaultAUD:      m.DefaultAUD,
		DefaultISSRange: m.DefaultISSRange,
	}
}

// VerifierMetaFromPB pb校验器元信息转核心,nil输入返回nil,算法无法识别时返回ErrAlgoType
func VerifierMetaFromPB(m *jwt_pb.VerifierMeta) (*jwthelper.VerifierMeta, error) {
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
func JwtStatusToPB(s *jwthelper.JwtStatus) *jwt_pb.JwtStatus {
	if s == nil {
		return nil
	}
	return &jwt_pb.JwtStatus{
		Jti:      s.Jti,
		Sub:      s.Sub,
		Iss:      s.Iss,
		TimeLeft: s.TimeLeft,
		Aud:      s.Aud,
	}
}

// JwtStatusFromPB pb校验状态转核心,nil输入返回nil(ExpAt置0,由调用方按需补充)
func JwtStatusFromPB(s *jwt_pb.JwtStatus) *jwthelper.JwtStatus {
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
