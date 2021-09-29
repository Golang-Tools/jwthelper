// verifier jwt校验器
package jwthelper

import (
	"testing"
	"time"

	"github.com/Golang-Tools/jwthelper/jwt_pb"
	"github.com/Golang-Tools/jwthelper/signoptions"
	"github.com/Golang-Tools/jwthelper/verifyoptions"
	"github.com/stretchr/testify/assert"
)

var token1 = jwt_pb.Token{AccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoxLCJiIjoiQiIsImV4cCI6MTYzMjc0MTk5MCwiaWF0IjoxNjMyNzQxMzkwLCJpc3MiOiIxY2MtSFMyNTYiLCJqdGkiOiI4ODYyZjk4Mi02N2RiLTQ5MzEtYjM2NS01MmVmYWIxZjUxNzIifQ.OiIO6KPadx_oVzHRJLJyGg9SW5YRkHKCM_JTql62LV0"}
var token2 = jwt_pb.Token{AccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoxLCJiIjoiQiIsImV4cCI6MTYzMjc0MTk5MCwiaWF0IjoxNjMyNzQxMzkwLCJpc3MiOiIxY2MtSFMyNTYiLCJqdGkiOiJjMTNkMWQ1My1kYWY4LTQ4MDItOTY0Yy05ZjNlZGRmZTgwN2UifQ.ZuVi6vR5IxsM5rKTBmsvl9JPYrOBN0B0D86g2IurLq4"}

var tokenwithrefresh = jwt_pb.Token{
	AccessToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoxLCJiIjoiQiIsImV4cCI6MTYzMjg4MTY0MCwiaWF0IjoxNjMyODgxMDQwLCJpc3MiOiIxY2MtSFMyNTYiLCJqdGkiOiJhZTA4YjYxZC1jNTBhLTRjNGYtYjRjMy1jMzhkMjA2YTk0MmIiLCJzdWIiOiJ0ZXN0In0.1BoEasg3StpHdAe79pM2AiIFAaC6MdemQ-rqrwrz-CU",
	RefreshToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MzI5Njc0NDAsImlhdCI6MTYzMjg4MTA0MCwiaXNzIjoiMWNjLUhTMjU2IiwianRpIjoiYWUwOGI2MWQtYzUwYS00YzRmLWI0YzMtYzM4ZDIwNmE5NDJiIiwic3ViIjoidGVzdCJ9.ZDnWUvkePBYIK3Ydq9RtCmz09oVs4UxQ87jWKT4Mna8",
}

//TestDefaultVerifierrMeta 测试默认校验器的元数据
func TestDefaultVerifierrMeta(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	res := verifier.Meta()
	t.Log("get algo", res.Algo.String())
	assert.Equal(t, jwt_pb.EncryptionAlgorithm_HS256, res.Algo)
	t.Log("get defaultAUD", res.DefaultAUD)
	assert.Equal(t, "", res.DefaultAUD)
	t.Log("get DefaultISSRange", res.DefaultISSRange)
	assert.Equal(t, []string{}, res.DefaultISSRange)
}

//TestNewHashVerifierWithOpts 测试带参数创建签名器
//注意没有设置iss,但iss应该会随着设置算法更改
func TestNewHashVerifierrOpts(t *testing.T) {
	verifier, err := NewVerifier(WithDefaultAUD("test"), WithDefaultISSRange("1cc-HS256"))

	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	res := verifier.Meta()
	t.Log("get algo", res.Algo.String())
	assert.Equal(t, jwt_pb.EncryptionAlgorithm_HS256, res.Algo)
	t.Log("get defaultAUD", res.DefaultAUD)
	assert.Equal(t, "test", res.DefaultAUD)
	t.Log("get DefaultISSRange", res.DefaultISSRange)
	assert.Contains(t, res.DefaultISSRange, "1cc-HS256")
}

//TestNewHashVerifierWithNewKey 测试创建签名器,改变key并更改iss
func TestNewHashVerifierWithNewKey(t *testing.T) {
	verifier, err := NewVerifier(
		WithVerifySecretKey([]byte("testkey")),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	key := string(verifier.key.([]byte))
	t.Log("get key", key)
	assert.Equal(t, "testkey", key)
}

//TestNewHashVerifierWithNewKeyInFile 测试从文件中读取秘钥
func TestNewHashVerifierWithNewKeyInFile(t *testing.T) {
	verifier, err := NewVerifier(
		WithVerifySecretKeyFromFile("key.txt"),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	key := string(verifier.key.([]byte))
	t.Log("get key", key)
	assert.Equal(t, "key in file", key)
}

//TestNewHashVerifierWithWrongKeyFilepath 测试从错误文件路径中读取秘钥
func TestNewHashVerifierWithWrongKeyFilepath(t *testing.T) {
	func() {
		defer func() {
			if err := recover(); err != nil {
				t.Log("get err", err.(error).Error())
			}
		}()
		NewVerifier(WithVerifySecretKeyFromFile("key.txt1"))
		assert.FailNow(t, "init signer should error")
	}()
}

//TestHashVerifierVerify 测试hash类型的签名校验器校验token
//测试的两个token的负载一样,但签名时间不同,而且都已经过期
func TestHashVerifierVerify(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}

	payload1 := testPayLoad{}
	payload2 := testPayLoad{}

	jti1, _, _ := verifier.Verify(&token1, &payload1)
	jti2, _, _ := verifier.Verify(&token2, &payload2)
	t.Log("get payload1", payload1)
	t.Log("get payload2", payload2)
	assert.EqualValues(t, payload1, payload2)
	t.Log("get jti1", jti1)
	t.Log("get jti2", jti2)
	assert.NotEqual(t, jti1, jti2)
}

//TestHashVerifierVerifyWithRefreshToken 测试校验带RefreshToken的签名
//测试的两个token的负载一样,但签名时间不同,而且已经过期
func TestHashVerifierVerifyWithRefreshToken(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}

	payload1 := testPayLoad{}
	payload2 := testPayLoad{}

	verifier.Verify(&token1, &payload1)
	verifier.Verify(&tokenwithrefresh, &payload2)
	t.Log("get payload1", payload1)
	t.Log("get payload2", payload2)
	assert.EqualValues(t, payload1, payload2)
}

//TestHashVerifierVerifyExpiredToken 测试解析只有access_token且已经过期的token
func TestHashVerifierVerifyExpiredToken(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}

	payload1 := testPayLoad{}
	_, timeleft, err := verifier.Verify(&token1, &payload1)
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get timeleft", timeleft)
	assert.Equal(t, time.Duration(0), timeleft)
	t.Log("get err", err)
	assert.EqualError(t, err, "EXP validation failed")
}

//TestHashVerifierVerifyNotAccessToken 测试解析的token不含AccessToken
func TestHashVerifierVerifyNotAccessToken(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}

	payload1 := testPayLoad{}
	_, timeleft, err := verifier.Verify(&jwt_pb.Token{}, &payload1)
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get timeleft", timeleft)
	assert.Equal(t, time.Duration(0), timeleft)
	t.Log("get payload", payload1)
	assert.Equal(t, 0, payload1.A)
	assert.Equal(t, "", payload1.B)
	t.Log("get err", err)
	assert.EqualError(t, err, "access token not found")
}

//TestHashVerifierVerifyNotToken 测试解析不是jwt的字符串
func TestHashVerifierVerifyNotToken(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}

	payload1 := testPayLoad{}
	_, timeleft, err := verifier.Verify(&jwt_pb.Token{AccessToken: "asfdasfsd"}, &payload1)
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get timeleft", timeleft)
	assert.Equal(t, time.Duration(0), timeleft)
	t.Log("get payload", payload1)
	assert.Equal(t, 0, payload1.A)
	assert.Equal(t, "", payload1.B)
	t.Log("get err", err)
	assert.EqualError(t, err, "token is malformed")
}

//TestHashVerifierVerifyOKAccessToken 测试校验一个access_token未过期的token
//需要注意map[string]interface{}类型的负载中int类型的数据会被转成float64型
func TestHashVerifierVerifyOKAccessToken(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	sub := "test"
	payload := map[string]interface{}{"a": 1.0, "b": "B"}
	token, err := signer.Sign(payload, signoptions.WithSub(sub))
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign get error")
	}
	payload1 := map[string]interface{}{}
	_, timeleft, err := verifier.Verify(token, &payload1)
	if err != nil {
		assert.FailNow(t, "verifier Verify should not get error")
	}
	t.Log("get timeleft", timeleft)
	assert.LessOrEqual(t, timeleft, time.Second*time.Duration(signer.Meta().DefaultTTL))
	t.Log("get payload", payload1)
	assert.EqualValues(t, payload, payload1)
}

//TestHashVerifierVerifyCheckMatch 测试校验的各种匹配情况
func TestHashVerifierVerifyCheckMatch(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	sub := "test"
	aud := "test_aud"
	payload := map[string]interface{}{"a": 1.0, "b": "B"}
	token, err := signer.Sign(
		payload,
		signoptions.WithSub(sub),
		signoptions.WithAud(aud))
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign get error")
	}
	payload1 := map[string]interface{}{}
	_, timeleft, err := verifier.Verify(
		token,
		&payload1,
		verifyoptions.WithSUBMustBe(sub),
		verifyoptions.WithAUDMustHas(aud),
		verifyoptions.WithIssMustIn(signer.opts.Iss))
	if err != nil {
		assert.FailNow(t, "verifier Verify should not get error")
	}
	t.Log("get timeleft", timeleft)
	assert.LessOrEqual(t, timeleft, time.Second*time.Duration(signer.Meta().DefaultTTL))
	t.Log("get payload", payload1)
	assert.EqualValues(t, payload, payload1)
}

//TestHashVerifierVerifyCheckSubNotMatch 测试校验sub不匹配
func TestHashVerifierVerifyCheckSubNotMatch(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	sub := "test"
	aud := "test_aud"
	payload := map[string]interface{}{"a": 1.0, "b": "B"}
	token, err := signer.Sign(
		payload,
		signoptions.WithSub(sub),
		signoptions.WithAud(aud))
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign get error")
	}
	payload1 := map[string]interface{}{}
	_, timeleft, err := verifier.Verify(
		token,
		&payload1,
		verifyoptions.WithSUBMustBe(sub+"1"),
		verifyoptions.WithAUDMustHas(aud),
		verifyoptions.WithIssMustIn(signer.opts.Iss))
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get timeleft", timeleft)
	assert.Equal(t, time.Duration(0), timeleft)
	t.Log("get err", err)
	assert.EqualError(t, err, "SUB validation failed")
}

//TestHashVerifierVerifyCheckAudNotMatch 测试校验aud不匹配
func TestHashVerifierVerifyCheckAudNotMatch(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	sub := "test"
	aud := "test_aud"
	payload := map[string]interface{}{"a": 1.0, "b": "B"}
	token, err := signer.Sign(
		payload,
		signoptions.WithSub(sub),
		signoptions.WithAud(aud))
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign get error")
	}
	payload1 := map[string]interface{}{}
	_, timeleft, err := verifier.Verify(
		token,
		&payload1,
		verifyoptions.WithSUBMustBe(sub),
		verifyoptions.WithAUDMustHas(aud+"1"),
		verifyoptions.WithIssMustIn(signer.opts.Iss))
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get timeleft", timeleft)
	assert.Equal(t, time.Duration(0), timeleft)
	t.Log("get err", err)
	assert.EqualError(t, err, "AUD validation failed")
}

//TestHashVerifierVerifyCheckIssNotMatch 测试校验iss不匹配
func TestHashVerifierVerifyCheckIssNotMatch(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	sub := "test"
	aud := "test_aud"
	payload := map[string]interface{}{"a": 1.0, "b": "B"}
	token, err := signer.Sign(
		payload,
		signoptions.WithSub(sub),
		signoptions.WithAud(aud))
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign get error")
	}
	payload1 := map[string]interface{}{}
	_, timeleft, err := verifier.Verify(
		token,
		&payload1,
		verifyoptions.WithSUBMustBe(sub),
		verifyoptions.WithAUDMustHas(aud),
		verifyoptions.WithIssMustIn(signer.opts.Iss+"1"))
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get timeleft", timeleft)
	assert.Equal(t, time.Duration(0), timeleft)
	t.Log("get err", err)
	assert.EqualError(t, err, "ISS validation failed")
}

//TestHashVerifierVerifyCheckAllNotMatch 测试校验全部不匹配
//校验顺序为sub>aud>iss所以应该报`SUB validation failed`
func TestHashVerifierVerifyCheckAllNotMatch(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	sub := "test"
	aud := "test_aud"
	payload := map[string]interface{}{"a": 1.0, "b": "B"}
	token, err := signer.Sign(
		payload,
		signoptions.WithSub(sub),
		signoptions.WithAud(aud))
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign get error")
	}
	payload1 := map[string]interface{}{}
	_, timeleft, err := verifier.Verify(
		token,
		&payload1,
		verifyoptions.WithSUBMustBe(sub+"1"),
		verifyoptions.WithAUDMustHas(aud+"1"),
		verifyoptions.WithIssMustIn(signer.opts.Iss+"1"))
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get timeleft", timeleft)
	assert.Equal(t, time.Duration(0), timeleft)
	t.Log("get err", err)
	assert.EqualError(t, err, "SUB validation failed")
}

//TestHashVerifierVerifyExpiredToken 测试解析有access_token且已经过期的token但有RefreshToken且没有过期的token
//请自己设置下`tokenwithrefresh`的值让它满足这个要求
func TestHashVerifierVerifyExpiredAccessTokenWithNotExpiredRefreshToken(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}

	payload1 := testPayLoad{}
	_, timeleft, err := verifier.Verify(&tokenwithrefresh, &payload1)
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get timeleft", timeleft)
	assert.LessOrEqual(t, time.Duration(0), timeleft)
	t.Log("get err", err)
	assert.EqualError(t, err, "EXP validation failed")
}

//TestHashVerifierVerifyNotToken 测试解析access_token过期,有refresh_token,但不是jwt的字符串的情况
// 这种情况下应该可以解析出payload,但报错不是超时
func TestHashVerifierVerifyNotRefreshTokenAccessTokenExpired(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	payload1 := testPayLoad{}
	_, timeleft, err := verifier.Verify(&jwt_pb.Token{AccessToken: token1.AccessToken, RefreshToken: "asfdasfsd"}, &payload1)
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get timeleft", timeleft)
	assert.Equal(t, time.Duration(0), timeleft)
	t.Log("get payload", payload1)
	assert.Equal(t, 1, payload1.A)
	assert.Equal(t, "B", payload1.B)
	t.Log("get err", err)
	assert.EqualError(t, err, "token contains an invalid number of segments")
}

//TestHashVerifierVerifyWithRefreshTokenCheckMatch 测试校验带RefreshToken的token的各种匹配情况
func TestHashVerifierVerifyWithRefreshTokenCheckMatch(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
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
	_, timeleft, err := verifier.Verify(
		token,
		&payload1,
		verifyoptions.WithSUBMustBe(sub),
		verifyoptions.WithAUDMustHas(aud),
		verifyoptions.WithIssMustIn(signer.opts.Iss))
	if err != nil {
		assert.FailNow(t, "verifier Verify should not get error")
	}
	t.Log("get timeleft", timeleft)
	assert.LessOrEqual(t, timeleft, time.Hour*24)
	t.Log("get payload", payload1)
}

//TestHashVerifierVerifyWithRefreshTokenCheckAllNotMatch 测试校验带RefreshToken的token的全部不匹配情况
func TestHashVerifierVerifyWithRefreshTokenCheckAllNotMatch(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
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
	_, timeleft, err := verifier.Verify(
		token,
		&payload1,
		verifyoptions.WithSUBMustBe(sub+"1"),
		verifyoptions.WithAUDMustHas(aud+"1"),
		verifyoptions.WithIssMustIn(signer.opts.Iss+"1"))
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get timeleft", timeleft)
	assert.Equal(t, time.Duration(0), timeleft)
	t.Log("get err", err)
	assert.EqualError(t, err, "SUB validation failed")
}

//TestHashVerifierVerifyWithRefreshTokenCheckRTSubNotMatch 测试校验带RefreshToken的token的两个key的sub不匹配
func TestHashVerifierVerifyWithRefreshTokenCheckRTSubNotMatch(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
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
	_, timeleft, err := verifier.Verify(
		token,
		&payload1)
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get timeleft", timeleft)
	assert.Equal(t, time.Duration(0), timeleft)
	t.Log("get err", err)
	assert.EqualError(t, err, "refresh token sub not match")
}

//TestHashVerifierVerifyWithRefreshTokenCheckRTWithoutSub 测试校验带RefreshToken的token的RefreshToken没有sub
func TestHashVerifierVerifyWithRefreshTokenCheckRTWithoutSub(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
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
	_, timeleft, err := verifier.Verify(
		token,
		&payload1)
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get timeleft", timeleft)
	assert.Equal(t, time.Duration(0), timeleft)
	t.Log("get err", err)
	assert.EqualError(t, err, "refresh token sub not match")
}

//TestHashVerifierVerifyWithRefreshTokenCheckRTNotMatchJti 校验jti不符的情况
func TestHashVerifierVerifyWithRefreshTokenCheckRTNotMatchJti(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
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
	jti, timeleft, err := verifier.Verify(
		token,
		&payload1,
	)
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get timeleft", timeleft)
	assert.Equal(t, time.Duration(0), timeleft)
	t.Log("get jti", jti)
	assert.NotEqual(t, "", jti)
	t.Log("get err", err)
	assert.EqualError(t, err, "refresh token jti not match")
}

//TestHashVerifierVerifyWithRefreshTokenCheckRTAUDNotMatch 测试校验带RefreshToken的token的两个key的aud不匹配
func TestHashVerifierVerifyWithRefreshTokenCheckRTAUDNotMatch(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
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
	_, timeleft, err := verifier.Verify(
		token,
		&payload1,
		verifyoptions.WithNotCheckRefreshTokenJTI())
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get timeleft", timeleft)
	assert.Equal(t, time.Duration(0), timeleft)
	t.Log("get err", err)
	assert.EqualError(t, err, "refresh token aud not match")
}

//TestHashVerifierVerifyWithRefreshTokenCheckRTIssNotInRange 测试校验带RefreshToken的token的RefreshToken的签发人不在合法范围
func TestHashVerifierVerifyWithRefreshTokenCheckRTIssNotInRange(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	otheriss := "otheriss"
	signer2, err := NewSigner(WithSignIss(otheriss))
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
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
	tokenfresh, err := signer2.Sign(
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
	_, timeleft, err := verifier.Verify(
		token,
		&payload1,
		verifyoptions.WithIssMustIn(signer.opts.Iss),
		verifyoptions.WithNotCheckRefreshTokenJTI(),
	)
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get timeleft", timeleft)
	assert.Equal(t, time.Duration(0), timeleft)
	t.Log("get err", err)
	assert.EqualError(t, err, "refresh token iss not in range")
}

//TestHashVerifierVerifyWithRefreshTokenCheckRTNotMatch 测试校验带RefreshToken的token的两个key的sub不匹配
func TestHashVerifierVerifyWithRefreshTokenCheckRTNotMatch(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
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
	_, timeleft, err := verifier.Verify(
		token,
		&payload1)
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get timeleft", timeleft)
	assert.Equal(t, time.Duration(0), timeleft)
	t.Log("get err", err)
	assert.EqualError(t, err, "refresh token sub not match")
}

//TestNewRSAVerifierrOpts 测试创建一个rsa算法的签名器
func TestNewRSAVerifierrOpts(t *testing.T) {
	verifier, err := NewVerifier(
		WithVerifyAlgo(jwt_pb.EncryptionAlgorithm_RS256),
		WithPemPublicKeyFromFile("utils/keygener/newkey_rsa_pub.pem"),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	res := verifier.Meta()
	t.Log("get algo", res.Algo.String())
	assert.Equal(t, jwt_pb.EncryptionAlgorithm_RS256, res.Algo)
	t.Log("get defaultAUD", res.DefaultAUD)
	assert.Equal(t, "", res.DefaultAUD)
	t.Log("get DefaultISSRange", res.DefaultISSRange)
	assert.Equal(t, []string{}, res.DefaultISSRange)
}

//TestNewESAVerifierrOpts  测试创建一个ecdsa算法的签名器
func TestNewESAVerifierrOpts(t *testing.T) {
	verifier, err := NewVerifier(
		WithVerifyAlgo(jwt_pb.EncryptionAlgorithm_ES256),
		WithPemPublicKeyFromFile("utils/keygener/newkey_ecdsa_pub.pem"),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	res := verifier.Meta()
	t.Log("get algo", res.Algo.String())
	assert.Equal(t, jwt_pb.EncryptionAlgorithm_ES256, res.Algo)
	t.Log("get defaultAUD", res.DefaultAUD)
	assert.Equal(t, "", res.DefaultAUD)
	t.Log("get DefaultISSRange", res.DefaultISSRange)
	assert.Equal(t, []string{}, res.DefaultISSRange)
}

//TestNewEdDSAAVerifierrOpts  测试创建一个ed25519算法的签名器
func TestNewEdDSAAVerifierrOpts(t *testing.T) {
	verifier, err := NewVerifier(
		WithVerifyAlgo(jwt_pb.EncryptionAlgorithm_EdDSA),
		WithPemPublicKeyFromFile("utils/keygener/newkey_ed25519_pub.pem"),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	res := verifier.Meta()
	t.Log("get algo", res.Algo.String())
	assert.Equal(t, jwt_pb.EncryptionAlgorithm_EdDSA, res.Algo)
	t.Log("get defaultAUD", res.DefaultAUD)
	assert.Equal(t, "", res.DefaultAUD)
	t.Log("get DefaultISSRange", res.DefaultISSRange)
	assert.Equal(t, []string{}, res.DefaultISSRange)
}

//TestRSAVerifierVerifyWithRefreshToken 测试校验rsa加密的带RefreshToken的签名
//测试的两个token的负载一样,但签名时间不同,而且已经过期
func TestRSAVerifierVerifyWithRefreshToken(t *testing.T) {
	verifier, err := NewVerifier(
		WithVerifyAlgo(jwt_pb.EncryptionAlgorithm_RS256),
		WithPemPublicKeyFromFile("utils/keygener/newkey_rsa_pub.pem"),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	signer, err := NewSigner(
		WithSignAlgo(jwt_pb.EncryptionAlgorithm_RS256),
		WithPemPrivateKeyFromFile("utils/keygener/newkey_rsa.pem"),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	token, err := signer.Sign(
		nil,
		signoptions.WithSub("test"),
		signoptions.WithRefreshTTL(time.Hour*24),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign should not get error ", err.Error())
	}
	payload := map[string]interface{}{}
	jti, timeleft, err := verifier.Verify(token, &payload)
	if err != nil {
		assert.FailNow(t, err.Error(), "verifier.Verify should not get error ", err.Error())
	}

	t.Log("get payload", payload)
	t.Log("get timeleft", timeleft)
	assert.LessOrEqual(t, timeleft, time.Hour*24)
	assert.NotEqual(t, "", jti)
}

//TestEcdsaVerifierVerifyWithRefreshToken 测试校验ecdsa加密的带RefreshToken的签名
//测试的两个token的负载一样,但签名时间不同,而且已经过期
func TestEcdsaVerifierVerifyWithRefreshToken(t *testing.T) {
	verifier, err := NewVerifier(
		WithVerifyAlgo(jwt_pb.EncryptionAlgorithm_ES256),
		WithPemPublicKeyFromFile("utils/keygener/newkey_ecdsa_pub.pem"),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	signer, err := NewSigner(
		WithSignAlgo(jwt_pb.EncryptionAlgorithm_ES256),
		WithPemPrivateKeyFromFile("utils/keygener/newkey_ecdsa.pem"),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	token, err := signer.Sign(
		nil,
		signoptions.WithSub("test"),
		signoptions.WithRefreshTTL(time.Hour*24),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign should not get error ", err.Error())
	}
	payload := map[string]interface{}{}
	jti, timeleft, err := verifier.Verify(token, &payload)
	if err != nil {
		assert.FailNow(t, err.Error(), "verifier.Verify should not get error ", err.Error())
	}

	t.Log("get payload", payload)
	t.Log("get timeleft", timeleft)
	assert.LessOrEqual(t, timeleft, time.Hour*24)
	assert.NotEqual(t, "", jti)
}

//TestEDsaVerifierVerifyWithRefreshToken 测试校验ed25519加密的带RefreshToken的签名
//测试的两个token的负载一样,但签名时间不同,而且已经过期
func TestEDsaVerifierVerifyWithRefreshToken(t *testing.T) {
	verifier, err := NewVerifier(
		WithVerifyAlgo(jwt_pb.EncryptionAlgorithm_EdDSA),
		WithPemPublicKeyFromFile("utils/keygener/newkey_ed25519_pub.pem"),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	signer, err := NewSigner(
		WithSignAlgo(jwt_pb.EncryptionAlgorithm_EdDSA),
		WithPemPrivateKeyFromFile("utils/keygener/newkey_ed25519.pem"),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	token, err := signer.Sign(
		nil,
		signoptions.WithSub("test"),
		signoptions.WithRefreshTTL(time.Hour*24),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign should not get error ", err.Error())
	}
	payload := map[string]interface{}{}
	jti, timeleft, err := verifier.Verify(token, &payload)
	if err != nil {
		assert.FailNow(t, err.Error(), "verifier.Verify should not get error ", err.Error())
	}

	t.Log("get payload", payload)
	t.Log("get timeleft", timeleft)
	assert.LessOrEqual(t, timeleft, time.Hour*24)
	assert.NotEqual(t, "", jti)
}
