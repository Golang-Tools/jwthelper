package utils

import (
	"testing"

	"github.com/Golang-Tools/jwthelper/v3/exceptions"
	"github.com/Golang-Tools/jwthelper/v3/jwt_pb"
	"github.com/stretchr/testify/assert"
)

//TestAlgoStrTOAlgoEnum 算法名到枚举的解析应覆盖全部算法且大小写不敏感
func TestAlgoStrTOAlgoEnum(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  jwt_pb.EncryptionAlgorithm
	}{
		{"HS256", "HS256", jwt_pb.EncryptionAlgorithm_HS256},
		{"HS384", "HS384", jwt_pb.EncryptionAlgorithm_HS384},
		{"HS512", "HS512", jwt_pb.EncryptionAlgorithm_HS512},
		{"RS256", "RS256", jwt_pb.EncryptionAlgorithm_RS256},
		{"RS384", "RS384", jwt_pb.EncryptionAlgorithm_RS384},
		{"RS512", "RS512", jwt_pb.EncryptionAlgorithm_RS512},
		{"ES256", "ES256", jwt_pb.EncryptionAlgorithm_ES256},
		{"ES384", "ES384", jwt_pb.EncryptionAlgorithm_ES384},
		{"ES512", "ES512", jwt_pb.EncryptionAlgorithm_ES512},
		{"EdDSA", "EdDSA", jwt_pb.EncryptionAlgorithm_EdDSA},
		{"EdDSA全大写", "EDDSA", jwt_pb.EncryptionAlgorithm_EdDSA},
		{"EdDSA全小写", "eddsa", jwt_pb.EncryptionAlgorithm_EdDSA},
		{"ES256小写", "es256", jwt_pb.EncryptionAlgorithm_ES256},
		{"HS256混合大小写", "hS256", jwt_pb.EncryptionAlgorithm_HS256},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := AlgoStrTOAlgoEnum(c.input)
			assert.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

//TestAlgoStrTOAlgoEnumInvalid 非法算法名返回ErrAlgoType
func TestAlgoStrTOAlgoEnumInvalid(t *testing.T) {
	got, err := AlgoStrTOAlgoEnum("none")
	assert.ErrorIs(t, err, exceptions.ErrAlgoType)
	assert.Equal(t, jwt_pb.EncryptionAlgorithm_UNKNOWN, got)
}

//TestIsAlgoHelpers 算法分类辅助函数
func TestIsAlgoHelpers(t *testing.T) {
	assert.True(t, IsSymmetric(jwt_pb.EncryptionAlgorithm_HS256))
	assert.True(t, IsSymmetric(jwt_pb.EncryptionAlgorithm_HS384))
	assert.True(t, IsSymmetric(jwt_pb.EncryptionAlgorithm_HS512))
	assert.False(t, IsSymmetric(jwt_pb.EncryptionAlgorithm_RS256))

	assert.True(t, IsAsymmetric(jwt_pb.EncryptionAlgorithm_RS256))
	assert.True(t, IsAsymmetric(jwt_pb.EncryptionAlgorithm_ES256))
	assert.True(t, IsAsymmetric(jwt_pb.EncryptionAlgorithm_EdDSA))
	assert.False(t, IsAsymmetric(jwt_pb.EncryptionAlgorithm_HS256))

	assert.True(t, IsEs(jwt_pb.EncryptionAlgorithm_ES256))
	assert.True(t, IsEs(jwt_pb.EncryptionAlgorithm_ES512))
	assert.False(t, IsEs(jwt_pb.EncryptionAlgorithm_RS256))

	assert.True(t, IsRs(jwt_pb.EncryptionAlgorithm_RS384))
	assert.False(t, IsRs(jwt_pb.EncryptionAlgorithm_ES384))

	assert.True(t, IsEdDSA(jwt_pb.EncryptionAlgorithm_EdDSA))
	assert.False(t, IsEdDSA(jwt_pb.EncryptionAlgorithm_HS256))
}

//TestLoadData 数据加载的边界情况
func TestLoadData(t *testing.T) {
	_, err := LoadData("")
	assert.Error(t, err)

	b, err := LoadData("+")
	assert.NoError(t, err)
	assert.Equal(t, []byte("{}"), b)

	_, err = LoadData("not-exists-file.txt")
	assert.Error(t, err)
}
