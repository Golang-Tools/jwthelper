package jwthelper

import (
	"context"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"

	"github.com/Golang-Tools/jwthelper/v4/signoptions"
	"github.com/stretchr/testify/assert"
)

// TestSignRefreshTokenNbf 回归:伴生refresh_token应携带nbf(历史上曾误写为nbr)
func TestSignRefreshTokenNbf(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	payload := testPayLoad{A: 1, B: "B", C: 1.2}
	nbf := time.Now().Add(-time.Minute).Unix()
	token, err := signer.Sign(
		context.Background(),
		payload,
		signoptions.WithSub("test"),
		signoptions.WithNbf(nbf),
		signoptions.WithRefreshTTL(time.Hour*24),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer.Sign get error")
	}
	assert.NotEmpty(t, token.RefreshToken)

	keyfunc := func(t *jwt.Token) (interface{}, error) {
		return []byte("a secret"), nil
	}
	parsed, err := jwt.Parse(token.RefreshToken, keyfunc)
	assert.NoError(t, err)
	refreshClaims, ok := parsed.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, float64(nbf), refreshClaims["nbf"], "refresh token 应包含 nbf")
	assert.Nil(t, refreshClaims["nbr"], "不应再出现错误的 nbr 键")

	parsedAccess, err := jwt.Parse(token.AccessToken, keyfunc)
	assert.NoError(t, err)
	accessClaims, ok := parsedAccess.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, float64(nbf), accessClaims["nbf"])
}
