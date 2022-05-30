package sdk

import (
	"testing"
	"time"

	"github.com/Golang-Tools/jwthelper/v2/jwt_pb"
	"github.com/Golang-Tools/jwthelper/v2/signoptions"
	"github.com/stretchr/testify/assert"
)

//TestSigner_Meta 测试meta接口
func TestSigner_Meta(t *testing.T) {
	config := SDKConfig{
		Query_Addresses: []string{"localhost:5000"},
	}
	sdk := config.NewSDK()
	signer, err := sdk.NewSigner()
	if err != nil {
		assert.FailNow(t, "sdk.NewSigner should not get error")
	}
	res, err := signer.Meta()
	if err != nil {
		assert.FailNow(t, "signer.Meta should not get error")
	}
	t.Log("get algo", res.Algo.String())
	assert.Equal(t, jwt_pb.EncryptionAlgorithm_HS256, res.Algo)
	t.Log("get jtigen", res.JtiGen)
	assert.Equal(t, "uuid4", res.JtiGen)
	t.Log("get DefaultTTL", res.DefaultTTL)
	assert.Equal(t, int64(600), res.DefaultTTL)
	t.Log("get DefaultEffectiveInterval", res.DefaultEffectiveInterval)
	assert.Equal(t, int64(0), res.DefaultEffectiveInterval)
	t.Log("get Iss", res.Iss)
	assert.Contains(t, res.Iss, res.Algo.String())
}

//TestHashSignerSign 测试签名器签名一个负载
//校验签名同一个负载结果不会一致(因为jti一定不一样)
func TestHashSignerSign(t *testing.T) {
	config := SDKConfig{
		Query_Addresses: []string{"localhost:5000"},
	}
	sdk := config.NewSDK()
	signer, err := sdk.NewSigner()
	if err != nil {
		assert.FailNow(t, "sdk.NewSigner should not get error")
	}
	payload := testPayLoad{
		A: 1,
		B: "B",
		C: 1.2,
	}
	token1, err := signer.Sign(payload)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer sign error")
	}

	t.Log("get RefreshToken", token1.RefreshToken)
	assert.Equal(t, "", token1.RefreshToken)
	token2, err := signer.Sign(payload)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer sign error")
	}
	t.Log("get access_token1", token1.AccessToken)
	t.Log("get access_token2", token2.AccessToken)
	assert.NotEqual(t, token1.AccessToken, token2.AccessToken)
}

//TestHashSignerSignPayloadNil 测试hash类型的签名器签名一个空的负载,空负载会被当做空map处理
func TestHashSignerSignPayloadNil(t *testing.T) {
	config := SDKConfig{
		Query_Addresses: []string{"localhost:5000"},
	}
	sdk := config.NewSDK()
	signer, err := sdk.NewSigner()
	if err != nil {
		assert.FailNow(t, "sdk.NewSigner should not get error")
	}
	token1, err := signer.Sign(nil)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer sign error")
	}

	t.Log("get RefreshToken", token1.RefreshToken)
	assert.Equal(t, "", token1.RefreshToken)
	t.Log("get access_token1", token1.AccessToken)

}

//TestHashSignerSignWithRefreshToken 测试hash类型的签名器签名一个负载,同时伴生生成一个RefreshToken
//校验签名同一个负载结果不会一致(因为jti一定不一样)
func TestHashSignerSignWithRefreshToken(t *testing.T) {
	config := SDKConfig{
		Query_Addresses: []string{"localhost:5000"},
	}
	sdk := config.NewSDK()
	signer, err := sdk.NewSigner()
	if err != nil {
		assert.FailNow(t, "sdk.NewSigner should not get error")
	}
	payload := testPayLoad{
		A: 1,
		B: "B",
		C: 1.2,
	}
	token1, err := signer.Sign(payload, signoptions.WithSub("test"), signoptions.WithRefreshTTL(time.Hour*24))
	if err != nil {
		assert.FailNow(t, err.Error(), "signer sign error")
	}
	t.Log("get RefreshToken", token1.RefreshToken)
	t.Log("get AccessToken", token1.AccessToken)
	assert.NotEqual(t, "", token1.RefreshToken)
}
