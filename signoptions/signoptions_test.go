package signoptions

import (
	"testing"

	"github.com/Golang-Tools/optparams"
	"github.com/stretchr/testify/assert"
)

// TestWithAudOrderAndDedup aud的合并应保序并去重(替换原mapset的随机顺序实现)
func TestWithAudOrderAndDedup(t *testing.T) {
	o := optparams.GetOption(new(SignOptions),
		WithAud("b", "a", "b"),
		WithAud("c", "a"),
		AddAud("d"),
		AddAud("b"),
	)
	assert.NotNil(t, o.Aud)
	assert.Equal(t, []string{"b", "a", "c", "d"}, o.Aud)
}

// TestWithAudSingle 单次设置的顺序保持
func TestWithAudSingle(t *testing.T) {
	o := optparams.GetOption(new(SignOptions), WithAud("x", "y", "z"))
	assert.Equal(t, []string{"x", "y", "z"}, o.Aud)
}
