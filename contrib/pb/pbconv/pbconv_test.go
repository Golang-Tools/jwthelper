package pbconv

import (
	"testing"

	"github.com/Golang-Tools/jwthelper/contrib/pb/jwtpb"
	jwthelper "github.com/Golang-Tools/jwthelper/v4"
	"github.com/Golang-Tools/jwthelper/v4/exceptions"
	"github.com/stretchr/testify/assert"
)

// TestAlgoRoundTrip 算法名与pb枚举应可双向无损转换
func TestAlgoRoundTrip(t *testing.T) {
	algos := []jwthelper.Algo{
		jwthelper.AlgoHS256, jwthelper.AlgoHS384, jwthelper.AlgoHS512,
		jwthelper.AlgoRS256, jwthelper.AlgoRS384, jwthelper.AlgoRS512,
		jwthelper.AlgoES256, jwthelper.AlgoES384, jwthelper.AlgoES512,
		jwthelper.AlgoEdDSA,
	}
	for _, a := range algos {
		pb := AlgoToPB(a)
		assert.NotEqual(t, jwtpb.EncryptionAlgorithm_UNKNOWN, pb)
		back, err := AlgoFromPB(pb)
		assert.NoError(t, err)
		assert.Equal(t, a, back)
	}
}

// TestAlgoUnknown 未知算法的边界处理
func TestAlgoUnknown(t *testing.T) {
	assert.Equal(t, jwtpb.EncryptionAlgorithm_UNKNOWN, AlgoToPB(jwthelper.Algo("XX000")))
	_, err := AlgoFromPB(jwtpb.EncryptionAlgorithm_UNKNOWN)
	assert.ErrorIs(t, err, exceptions.ErrAlgoType)
}

// TestTokenRoundTrip 令牌双向转换
func TestTokenRoundTrip(t *testing.T) {
	token := &jwthelper.Token{AccessToken: "a", RefreshToken: "r"}
	pb := TokenToPB(token)
	assert.Equal(t, "a", pb.AccessToken)
	back := TokenFromPB(pb)
	assert.Equal(t, token, back)

	assert.Nil(t, TokenToPB(nil))
	assert.Equal(t, &jwthelper.Token{}, TokenFromPB(nil))
}

// TestSignerMetaRoundTrip 签名器元信息双向转换
func TestSignerMetaRoundTrip(t *testing.T) {
	m := &jwthelper.SignerMeta{
		Algo:                     jwthelper.AlgoES256,
		Iss:                      "test-iss",
		DefaultTTL:               600,
		DefaultEffectiveInterval: 5,
		JtiGen:                   "uuid4",
	}
	pb := SignerMetaToPB(m)
	assert.Equal(t, jwtpb.EncryptionAlgorithm_ES256, pb.Algo)
	back, err := SignerMetaFromPB(pb)
	assert.NoError(t, err)
	assert.Equal(t, m, back)

	assert.Nil(t, SignerMetaToPB(nil))
	pm, err := SignerMetaFromPB(nil)
	assert.NoError(t, err)
	assert.Nil(t, pm)
}

// TestVerifierMetaRoundTrip 校验器元信息双向转换
func TestVerifierMetaRoundTrip(t *testing.T) {
	m := &jwthelper.VerifierMeta{
		Algo:            jwthelper.AlgoRS384,
		DefaultAUD:      "test-aud",
		DefaultISSRange: []string{"a", "b"},
	}
	pb := VerifierMetaToPB(m)
	assert.Equal(t, jwtpb.EncryptionAlgorithm_RS384, pb.Algo)
	back, err := VerifierMetaFromPB(pb)
	assert.NoError(t, err)
	assert.Equal(t, m, back)

	assert.Nil(t, VerifierMetaToPB(nil))
	pm, err := VerifierMetaFromPB(nil)
	assert.NoError(t, err)
	assert.Nil(t, pm)
}

// TestJwtStatusRoundTrip 校验状态双向转换,ExpAt不参与pb传输(保留在接收方按需补充)
func TestJwtStatusRoundTrip(t *testing.T) {
	s := &jwthelper.JwtStatus{
		Jti:      "jti",
		Sub:      "sub",
		Iss:      "iss",
		Aud:      []string{"a"},
		ExpAt:    1234567890,
		TimeLeft: 50,
	}
	pb := JwtStatusToPB(s)
	assert.Equal(t, int64(50), pb.TimeLeft)
	back := JwtStatusFromPB(pb)
	assert.Equal(t, "jti", back.Jti)
	assert.Equal(t, "sub", back.Sub)
	assert.Equal(t, "iss", back.Iss)
	assert.Equal(t, []string{"a"}, back.Aud)
	assert.Equal(t, int64(50), back.TimeLeft)
	assert.Equal(t, int64(0), back.ExpAt, "pb当前没有exp_at字段,回程ExpAt为0")

	assert.Nil(t, JwtStatusToPB(nil))
	assert.Nil(t, JwtStatusFromPB(nil))
}
