package sdk

import (
	"testing"
	"time"

	"github.com/Golang-Tools/jwthelper/jwt_pb"
	"github.com/Golang-Tools/jwthelper/signoptions"
	"github.com/stretchr/testify/assert"
)

func TestDefaultVerifierrMeta(t *testing.T) {
	config := SDKConfig{
		Query_Addresses: []string{"localhost:5001"},
	}
	sdk := config.NewSDK()
	verifier, err := sdk.NewVerifier()
	if err != nil {
		assert.FailNow(t, "sdk.NewVerifier should not get error")
	}
	res, err := verifier.Meta()
	if err != nil {
		assert.FailNow(t, "signer.Meta should not get error")
	}
	t.Log("get algo", res.Algo.String())
	assert.Equal(t, jwt_pb.EncryptionAlgorithm_HS256, res.Algo)
	t.Log("get defaultAUD", res.DefaultAUD)
	assert.Equal(t, "", res.DefaultAUD)
	t.Log("get DefaultISSRange", res.DefaultISSRange)
	assert.Equal(t, []string{}, res.DefaultISSRange)
}

//TestHashVerifierVerify 测试hash类型的签名校验器校验token
//测试的两个token的负载一样,但签名时间不同,而且都已经过期
func TestHashVerifierVerify(t *testing.T) {
	config := SDKConfig{
		Query_Addresses: []string{"localhost:5001"},
	}
	sdk := config.NewSDK()
	verifier, err := sdk.NewVerifier()
	if err != nil {
		assert.FailNow(t, "sdk.NewVerifier should not get error")
	}
	config2 := SDKConfig{
		Query_Addresses: []string{"localhost:5000"},
	}
	sdk2 := config2.NewSDK()
	signer, err := sdk2.NewSigner()
	if err != nil {
		assert.FailNow(t, "sdk.NewSigner should not get error")
	}
	payload := testPayLoad{
		A: 1,
		B: "B",
	}
	token, err := signer.Sign(payload, signoptions.WithSub("test"), signoptions.WithRefreshTTL(time.Hour*24))
	if err != nil {
		assert.FailNow(t, err.Error(), "signer sign error")
	}

	payload1 := testPayLoad{}
	jti, timeleft, err := verifier.Verify(token, &payload1)
	if err != nil {
		assert.FailNow(t, "verifier Verify should not get error")
	}
	t.Log("get payload1", payload1)
	t.Log("get payload2", payload)
	assert.EqualValues(t, payload1, payload)
	t.Log("get jti", jti)
	assert.NotEqual(t, "", jti)
	t.Log("get timeleft", timeleft)
	assert.LessOrEqual(t, timeleft, time.Hour*24)
}
