package sdk

import (
	"testing"
	"time"

	"github.com/Golang-Tools/jwthelper/v2/jwt_pb"
	"github.com/Golang-Tools/jwthelper/v2/signoptions"
	"github.com/Golang-Tools/jwthelper/v2/verifyoptions"
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
	token, err := signer.Sign(payload, signoptions.WithSub("test"), signoptions.WithAud("aud1", "aud2"), signoptions.WithRefreshTTL(time.Hour*24))
	if err != nil {
		assert.FailNow(t, err.Error(), "signer sign error")
	}

	payload1 := testPayLoad{}
	res, err := verifier.Verify(token, &payload1)
	if err != nil {
		assert.FailNow(t, "verifier Verify should not get error")
	}
	t.Log("get payload1", payload1)
	t.Log("get payload2", payload)
	assert.EqualValues(t, payload1, payload)
	t.Log("get jti", res.Jti)
	assert.NotEqual(t, "", res.Jti)
	t.Log("get timeleft", res.TimeLeft)
	assert.LessOrEqual(t, res.TimeLeft, time.Hour*24)
	t.Log("get Sub", res.Sub)
	assert.Equal(t, "test", res.Sub)
	t.Log("get Aud", res.Aud)
	assert.Contains(t, res.Aud, "aud1")
	assert.Contains(t, res.Aud, "aud2")
}

//TestHashVerifierVerifyWithRefreshTokenCheckAllNotMatch 测试校验带RefreshToken的token的全部不匹配情况
func TestHashVerifierVerifyWithRefreshTokenCheckAllNotMatch(t *testing.T) {
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
	signermeta, err := signer.Meta()
	if err != nil {
		assert.FailNow(t, "signer.Meta should not get error")
	}

	sub := "test"
	aud := "test_aud"
	payload := map[string]interface{}{"a": 1.0, "b": "B"}
	token, err := signer.Sign(
		payload,
		signoptions.WithSub(sub),
		signoptions.WithAud(aud),
		signoptions.WithRefreshTTL(time.Hour*24),
	)

	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign get error")
	}
	payload1 := map[string]interface{}{}
	status, err := verifier.Verify(
		token,
		&payload1,
		verifyoptions.WithSUBMustBe(sub+"1"),
		verifyoptions.WithAUDMustHas(aud+"1"),
		verifyoptions.WithIssMustIn(signermeta.Iss+"1"))
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get status", status)
	assert.Nil(t, status)
	t.Log("get err", err)
	assert.EqualError(t, err, "SUB validation failed")
}

//TestHashVerifierVerifyWithRefreshTokenCheckRTSubNotMatch 测试校验带RefreshToken的token的两个key的sub不匹配
func TestHashVerifierVerifyWithRefreshTokenCheckRTSubNotMatch(t *testing.T) {
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
	sub := "test"
	payload := map[string]interface{}{"a": 1.0, "b": "B"}
	tokenacc, err := signer.Sign(
		payload,
		signoptions.WithSub(sub),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign get error")
	}
	tokenfresh, err := signer.Sign(
		nil,
		signoptions.WithSub(sub+"1"),
		signoptions.WithTTL(time.Hour*2),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign get error")
	}
	token := &jwt_pb.Token{
		AccessToken:  tokenacc.AccessToken,
		RefreshToken: tokenfresh.AccessToken,
	}
	payload1 := map[string]interface{}{}
	status, err := verifier.Verify(
		token,
		&payload1)
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get status", status)
	assert.Nil(t, status)
	t.Log("get err", err)
	assert.EqualError(t, err, "refresh token sub not match")
}

//TestHashVerifierVerifyWithRefreshTokenCheckRTWithoutSub 测试校验带RefreshToken的token的RefreshToken没有sub
func TestHashVerifierVerifyWithRefreshTokenCheckRTWithoutSub(t *testing.T) {
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
	sub := "test"
	payload := map[string]interface{}{"a": 1.0, "b": "B"}
	tokenacc, err := signer.Sign(
		payload,
		signoptions.WithSub(sub),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign get error")
	}
	tokenfresh, err := signer.Sign(
		nil,
		signoptions.WithTTL(time.Hour*2),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign get error")
	}
	token := &jwt_pb.Token{
		AccessToken:  tokenacc.AccessToken,
		RefreshToken: tokenfresh.AccessToken,
	}
	payload1 := map[string]interface{}{}
	status, err := verifier.Verify(
		token,
		&payload1)
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get status", status)
	assert.Nil(t, status)
	t.Log("get err", err)
	assert.EqualError(t, err, "refresh token sub not match")
}

//TestHashVerifierVerifyWithRefreshTokenCheckRTNotMatchJti 校验jti不符的情况
func TestHashVerifierVerifyWithRefreshTokenCheckRTNotMatchJti(t *testing.T) {
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
	sub := "test"
	aud := "test_aud"
	payload := map[string]interface{}{"a": 1.0, "b": "B"}
	tokenacc, err := signer.Sign(
		payload,
		signoptions.WithSub(sub),
		signoptions.WithAud(aud),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign get error")
	}
	tokenfresh, err := signer.Sign(
		nil,
		signoptions.WithSub(sub),
		signoptions.WithAud(aud),
		signoptions.WithTTL(time.Hour*2),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign get error")
	}
	token := &jwt_pb.Token{
		AccessToken:  tokenacc.AccessToken,
		RefreshToken: tokenfresh.AccessToken,
	}
	payload1 := map[string]interface{}{}
	status, err := verifier.Verify(
		token,
		&payload1,
	)
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get status", status)
	assert.Nil(t, status)
	t.Log("get err", err)
	assert.EqualError(t, err, "refresh token jti not match")
}

//TestHashVerifierVerifyWithRefreshTokenCheckRTAUDNotMatch 测试校验带RefreshToken的token的两个key的aud不匹配
func TestHashVerifierVerifyWithRefreshTokenCheckRTAUDNotMatch(t *testing.T) {
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
	sub := "test"
	aud := "test_aud"
	payload := map[string]interface{}{"a": 1.0, "b": "B"}
	tokenacc, err := signer.Sign(
		payload,
		signoptions.WithSub(sub),
		signoptions.WithAud(aud),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign get error")
	}
	tokenfresh, err := signer.Sign(
		nil,
		signoptions.WithSub(sub),
		signoptions.WithAud(aud+"1"),
		signoptions.WithTTL(time.Hour*2),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign get error")
	}
	token := &jwt_pb.Token{
		AccessToken:  tokenacc.AccessToken,
		RefreshToken: tokenfresh.AccessToken,
	}
	payload1 := map[string]interface{}{}
	status, err := verifier.Verify(
		token,
		&payload1,
		verifyoptions.WithNotCheckRefreshTokenJTI())
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get status", status)
	assert.Nil(t, status)
	t.Log("get err", err)
	assert.EqualError(t, err, "refresh token aud not match")
}

//TestHashVerifierVerifyWithRefreshTokenCheckRTNotMatch 测试校验带RefreshToken的token的两个key的sub不匹配
func TestHashVerifierVerifyWithRefreshTokenCheckRTNotMatch(t *testing.T) {
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
	sub := "test"
	aud := "test_aud"
	payload := map[string]interface{}{"a": 1.0, "b": "B"}
	tokenacc, err := signer.Sign(
		payload,
		signoptions.WithSub(sub),
		signoptions.WithAud(aud),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign get error")
	}
	tokenfresh, err := signer.Sign(
		nil,
		signoptions.WithSub(sub+"1"),
		signoptions.WithAud(aud+"1"),
		signoptions.WithTTL(time.Hour*2),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign get error")
	}
	token := &jwt_pb.Token{
		AccessToken:  tokenacc.AccessToken,
		RefreshToken: tokenfresh.AccessToken,
	}
	payload1 := map[string]interface{}{}
	status, err := verifier.Verify(
		token,
		&payload1)
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get status", status)
	assert.Nil(t, status)
	t.Log("get err", err)
	assert.EqualError(t, err, "refresh token sub not match")
}
