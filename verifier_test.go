// verifier jwt校验器
package jwthelper

import (
	"testing"
	"time"

	"github.com/Golang-Tools/jwthelper/jwt_pb"
	"github.com/stretchr/testify/assert"
)

var token1 = jwt_pb.Token{AccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoxLCJiIjoiQiIsImV4cCI6MTYzMjc0MTk5MCwiaWF0IjoxNjMyNzQxMzkwLCJpc3MiOiIxY2MtSFMyNTYiLCJqdGkiOiI4ODYyZjk4Mi02N2RiLTQ5MzEtYjM2NS01MmVmYWIxZjUxNzIifQ.OiIO6KPadx_oVzHRJLJyGg9SW5YRkHKCM_JTql62LV0"}
var token2 = jwt_pb.Token{AccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoxLCJiIjoiQiIsImV4cCI6MTYzMjc0MTk5MCwiaWF0IjoxNjMyNzQxMzkwLCJpc3MiOiIxY2MtSFMyNTYiLCJqdGkiOiJjMTNkMWQ1My1kYWY4LTQ4MDItOTY0Yy05ZjNlZGRmZTgwN2UifQ.ZuVi6vR5IxsM5rKTBmsvl9JPYrOBN0B0D86g2IurLq4"}

var tokenwithrefresh = jwt_pb.Token{
	AccessToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoxLCJiIjoiQiIsImV4cCI6MTYzMjc0MjY5NiwiaWF0IjoxNjMyNzQyMDk2LCJpc3MiOiIxY2MtSFMyNTYiLCJqdGkiOiI3ODA3MmIwOC0yNDRhLTRmZGEtYmEzMi05NTNlZGM4ZTM4YTkifQ.KqS54Uw-otNDR7XGHBbTyMPAd0jD9kewQANEuimHbm0",
	RefreshToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOm51bGwsImV4cCI6MTYzMjgyODQ5NiwiaXNzIjoiMWNjLUhTMjU2Iiwic3ViIjoiIn0.cRMYNahdOfYgfQxmJMfemoAvbO7in4Osuk5tQp-RfMU",
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

	verifier.Verify(&token1, &payload1)
	verifier.Verify(&token2, &payload2)
	t.Log("get payload1", payload1)
	t.Log("get payload2", payload2)
	assert.EqualValues(t, payload1, payload2)
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
	timeleft, err := verifier.Verify(&token1, &payload1)
	if err == nil {
		assert.FailNow(t, "verifier Verify should get error")
	}
	t.Log("get timeleft", timeleft)
	assert.Equal(t, time.Duration(0), timeleft)
	t.Log("get err", err)
	assert.EqualError(t, err, "EXP validation failed")
}

//TestHashVerifierVerifyExpiredToken 测试解析有access_token且已经过期的token但有RefreshToken且没有过期的token
//请自己设置下`tokenwithrefresh`的值让它满足这个要求
func TestHashVerifierVerifyExpiredAccessTokenWithNotExpiredRefreshToken(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}

	payload1 := testPayLoad{}
	timeleft, err := verifier.Verify(&tokenwithrefresh, &payload1)
	if err != nil {
		assert.FailNow(t, "verifier Verify should not get error")
	}
	t.Log("get timeleft", timeleft)
	assert.LessOrEqual(t, time.Duration(0), timeleft)
}
