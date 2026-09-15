package exceptions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestKindOfAndSentinelByKindRoundTrip 分类名与哨兵错误应一一对应
func TestKindOfAndSentinelByKindRoundTrip(t *testing.T) {
	sentinels := []error{
		ErrValidationErrorExpired,
		ErrValidationErrorMalformed,
		ErrValidationErrorUnverifiable,
		ErrValidationErrorSignatureInvalid,
		ErrValidationErrorAudience,
		ErrValidationErrorSubject,
		ErrValidationErrorIssuedAt,
		ErrValidationErrorIssuer,
		ErrValidationErrorNotValidYet,
		ErrValidationErrorId,
		ErrValidationErrorClaimsInvalid,
		ErrValidationErrorCanNotHandle,
		ErrValidationErrorUnknown,
		ErrAccessTokenNotFound,
		ErrSignWithRefreshTokenNeedSUB,
		ErrRefreshTokenNotHaveEXP,
		ErrRefreshTokenSUBNotMatch,
		ErrRefreshTokenAudNotMatch,
		ErrRefreshTokenJtiNotMatch,
		ErrRefreshTokenIssNotInRange,
		ErrRefreshTokenValidationError,
		ErrRefreshTokenParseError,
		ErrAlgoType,
		ErrUnsupportAlgoType,
		ErrAlgoTypeNotMatch,
	}
	for _, s := range sentinels {
		kind := KindOf(s)
		assert.NotEqual(t, "", kind, "哨兵错误必须有分类名")
		assert.NotEqual(t, "unknown", kind, "哨兵错误不能落入unknown分类")
		assert.Equal(t, s, SentinelByKind(kind), "分类名应可反查回原哨兵错误")
	}
}

// TestKindOfWrapped ValidationError包装后的错误仍可分类,且保留字段信息
func TestKindOfWrapped(t *testing.T) {
	err := &ValidationError{Field: "sub", Err: ErrValidationErrorSubject}
	assert.Equal(t, "validation_subject", KindOf(err))
	assert.ErrorIs(t, err, ErrValidationErrorSubject)
	assert.Equal(t, "sub : SUB validation failed", err.Error())
}

// TestKindOfNil 空错误与未知分类的边界处理
func TestKindOfNil(t *testing.T) {
	assert.Equal(t, "", KindOf(nil))
	assert.Nil(t, SentinelByKind(""))
	assert.Nil(t, SentinelByKind("not-exist-kind"))
	assert.Equal(t, "unknown", KindOf(assert.AnError))
}
