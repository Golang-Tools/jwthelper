package jwthelper

import (
	"context"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"

	"github.com/stretchr/testify/assert"
)

// signRawClaims 用默认key(HS256)直接签一组原始claims,用于构造含非法类型的载荷
func signRawClaims(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := token.SignedString([]byte("a secret"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestVerifyMaliciousClaimsNoPanic 校验含非法类型claims的token时应返回错误而不是panic
func TestVerifyMaliciousClaimsNoPanic(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	cases := []struct {
		name   string
		claims jwt.MapClaims
	}{
		{"exp非数字", jwt.MapClaims{"sub": "test", "exp": "not-a-number"}},
		{"aud数组含数字", jwt.MapClaims{"sub": "test", "aud": []interface{}{1, 2}}},
		{"aud数组含bool", jwt.MapClaims{"sub": "test", "aud": []interface{}{true, "a"}}},
		{"aud为null", jwt.MapClaims{"sub": "test", "aud": nil}},
		{"aud为数字", jwt.MapClaims{"sub": "test", "aud": 123}},
		{"sub非字符串", jwt.MapClaims{"sub": 123}},
		{"jti非字符串", jwt.MapClaims{"sub": "test", "jti": 123}},
		{"iss非字符串", jwt.MapClaims{"sub": "test", "iss": []interface{}{"a"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			token := Token{AccessToken: signRawClaims(t, c.claims)}
			payload := testPayLoad{}
			assert.NotPanics(t, func() {
				status, err := verifier.Verify(context.Background(), &token, &payload)
				t.Log(status, err)
			})
		})
	}
}

// TestVerifyMaliciousRefreshClaimsNoPanic 校验伴生refresh_token含非法类型claims时应返回错误而不是panic
func TestVerifyMaliciousRefreshClaimsNoPanic(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		assert.FailNow(t, err.Error(), "init verifier error")
	}
	// access_token 未过期且正常
	access := signRawClaims(t, jwt.MapClaims{
		"sub": "test",
		"aud": []interface{}{"x"},
		"jti": "jti1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	cases := []struct {
		name    string
		refresh jwt.MapClaims
	}{
		{"refresh-exp非数字", jwt.MapClaims{"sub": "test", "jti": "jti1", "exp": "foo"}},
		{"refresh-sub非字符串", jwt.MapClaims{"sub": 123, "jti": "jti1", "exp": time.Now().Add(time.Hour).Unix()}},
		{"refresh-jti非字符串", jwt.MapClaims{"sub": "test", "jti": 123, "exp": time.Now().Add(time.Hour).Unix()}},
		{"refresh-aud为数字", jwt.MapClaims{"sub": "test", "jti": "jti1", "aud": 123, "exp": time.Now().Add(time.Hour).Unix()}},
		{"refresh-aud数组含数字", jwt.MapClaims{"sub": "test", "jti": "jti1", "aud": []interface{}{1}, "exp": time.Now().Add(time.Hour).Unix()}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			token := Token{AccessToken: access, RefreshToken: signRawClaims(t, c.refresh)}
			payload := testPayLoad{}
			assert.NotPanics(t, func() {
				status, err := verifier.Verify(context.Background(), &token, &payload)
				t.Log(status, err)
			})
		})
	}
}
