package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLoadData 数据加载的边界情况
func TestLoadData(t *testing.T) {
	_, err := LoadData("")
	assert.Error(t, err)

	b, err := LoadData("+")
	assert.NoError(t, err)
	assert.Equal(t, []byte("{}"), b)

	_, err = LoadData("not-exists-file.txt")
	assert.Error(t, err)
}
