// signer jwt的签名器

package jwthelper

import (
	"testing"
	"time"

	"github.com/Golang-Tools/idgener"
	"github.com/Golang-Tools/jwthelper/v2/jwt_pb"
	"github.com/Golang-Tools/jwthelper/v2/signoptions"
	"github.com/stretchr/testify/assert"
)

//TestDefaultSignerMeta 测试默认签名器
func TestDefaultSignerMeta(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	res, _ := signer.Meta()
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

//TestNewHashSignerWithOpts 测试带参数创建签名器
//注意没有设置iss,但iss应该会随着设置算法更改
func TestNewHashSignerWithOpts(t *testing.T) {
	signer, err := NewSigner(
		WithSignAlgo(jwt_pb.EncryptionAlgorithm_HS512),
		WithSignJtiGen(idgener.DefaultSonyflake),
		WithDefaultEffectiveInterval(time.Second*15),
		WithDefaultTTL(time.Second*60*5),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	res, _ := signer.Meta()
	t.Log("get algo", res.Algo.String())
	assert.Equal(t, jwt_pb.EncryptionAlgorithm_HS512, res.Algo)
	t.Log("get jtigen", res.JtiGen)
	assert.Equal(t, "sonyflake", res.JtiGen)
	t.Log("get DefaultTTL", res.DefaultTTL)
	assert.Equal(t, int64(300), res.DefaultTTL)
	t.Log("get DefaultEffectiveInterval", res.DefaultEffectiveInterval)
	assert.Equal(t, int64(15), res.DefaultEffectiveInterval)
	t.Log("get Iss", res.Iss)
	assert.Contains(t, res.Iss, res.Algo.String())
}

//TestNewHashSignerWithNewKey 测试创建签名器,改变key并更改iss
func TestNewHashSignerWithNewKey(t *testing.T) {
	signer, err := NewSigner(
		WithSignIss("test"),
		WithSignSecretKey([]byte("testkey")),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	res, _ := signer.Meta()
	t.Log("get Iss", res.Iss)
	assert.Equal(t, "test", res.Iss)
	key := string(signer.key.([]byte))
	t.Log("get key", key)
	assert.Equal(t, "testkey", key)
}

//TestNewHashSignerWithNewKeyInFile 测试从文件中读取秘钥
func TestNewHashSignerWithNewKeyInFile(t *testing.T) {
	signer, err := NewSigner(
		WithSignIss("test"),
		WithSignSecretKeyFromFile("key.txt"),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	res, _ := signer.Meta()
	t.Log("get Iss", res.Iss)
	assert.Equal(t, "test", res.Iss)
	key := string(signer.key.([]byte))
	t.Log("get key", key)
	assert.Equal(t, "key in file", key)
}

//TestNewHashSignerWithWrongKeyFilepath 测试从错误文件路径中读取秘钥
func TestNewHashSignerWithWrongKeyFilepath(t *testing.T) {
	func() {
		defer func() {
			if err := recover(); err != nil {
				t.Log("get err", err.(error).Error())
			}
		}()
		NewSigner(WithSignSecretKeyFromFile("key.txt1"))
		assert.FailNow(t, "init signer should error")
	}()
}

//TestHashSignerSign 测试hash类型的签名器签名一个负载
//校验签名同一个负载结果不会一致(因为jti一定不一样)
func TestHashSignerSign(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
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
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	token1, err := signer.Sign(nil)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer sign error")
	}

	t.Log("get RefreshToken", token1.RefreshToken)
	assert.Equal(t, "", token1.RefreshToken)
	t.Log("get access_token1", token1.AccessToken)

}

//TestHashSignerSignPayloadEmpty 测试hash类型的签名器签名一个无内容的负载
func TestHashSignerSignPayloadEmpty(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	payload := testPayLoad{}
	token1, err := signer.Sign(payload)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer sign error")
	}

	t.Log("get RefreshToken", token1.RefreshToken)
	assert.Equal(t, "", token1.RefreshToken)
	t.Log("get access_token1", token1.AccessToken)
}

//TestHashSignerSignPayloadEmpty 测试hash类型的签名器签名一个无内容的map
func TestHashSignerSignPayloadEmptyMap(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	payload := map[string]interface{}{}
	token1, err := signer.Sign(payload)
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
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
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

//TestHashSignerSignWithRefreshTokenWithoutSUB 测试签名带伴生RefreshToken的签名时不设置SUB
//校验签名同一个负载结果不会一致(因为jti一定不一样)
func TestHashSignerSignWithRefreshTokenWithoutSUB(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	payload := testPayLoad{
		A: 1,
		B: "B",
		C: 1.2,
	}
	_, err = signer.Sign(payload, signoptions.WithRefreshTTL(time.Hour*24))
	if err == nil {
		assert.FailNow(t, err.Error(), "signer sign should get error")
	}
	t.Log("get err", err.Error())
	assert.EqualError(t, err, "sign with refresh token need SUB")
}

//TestNewRSASignerMeta 测试创建一个RSA的签名器
func TestNewRSASignerMeta(t *testing.T) {
	signer, err := NewSigner(
		WithSignAlgo(jwt_pb.EncryptionAlgorithm_RS256),
		WithPemPrivateKeyFromFile("utils/keygener/newkey_rsa.pem"),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	res, _ := signer.Meta()
	t.Log("get algo", res.Algo.String())
	assert.Equal(t, jwt_pb.EncryptionAlgorithm_RS256, res.Algo)
	t.Log("get jtigen", res.JtiGen)
	assert.Equal(t, "uuid4", res.JtiGen)
	t.Log("get DefaultTTL", res.DefaultTTL)
	assert.Equal(t, int64(600), res.DefaultTTL)
	t.Log("get DefaultEffectiveInterval", res.DefaultEffectiveInterval)
	assert.Equal(t, int64(0), res.DefaultEffectiveInterval)
	t.Log("get Iss", res.Iss)
	assert.Contains(t, res.Iss, res.Algo.String())
}

//TestNewESSignerMeta 测试创建一个Ecdsa的签名器
func TestNewESSignerMeta(t *testing.T) {
	signer, err := NewSigner(
		WithSignAlgo(jwt_pb.EncryptionAlgorithm_ES256),
		WithPemPrivateKeyFromFile("utils/keygener/newkey_ecdsa.pem"),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	res, _ := signer.Meta()
	t.Log("get algo", res.Algo.String())
	assert.Equal(t, jwt_pb.EncryptionAlgorithm_ES256, res.Algo)
	t.Log("get jtigen", res.JtiGen)
	assert.Equal(t, "uuid4", res.JtiGen)
	t.Log("get DefaultTTL", res.DefaultTTL)
	assert.Equal(t, int64(600), res.DefaultTTL)
	t.Log("get DefaultEffectiveInterval", res.DefaultEffectiveInterval)
	assert.Equal(t, int64(0), res.DefaultEffectiveInterval)
	t.Log("get Iss", res.Iss)
	assert.Contains(t, res.Iss, res.Algo.String())
}

//TestNewEdDSASignerMeta 测试创建一个EdDSA的签名器
func TestNewEdDSASignerMeta(t *testing.T) {
	signer, err := NewSigner(
		WithSignAlgo(jwt_pb.EncryptionAlgorithm_EdDSA),
		WithPemPrivateKeyFromFile("utils/keygener/newkey_ed25519.pem"),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	res, _ := signer.Meta()
	t.Log("get algo", res.Algo.String())
	assert.Equal(t, jwt_pb.EncryptionAlgorithm_EdDSA, res.Algo)
	t.Log("get jtigen", res.JtiGen)
	assert.Equal(t, "uuid4", res.JtiGen)
	t.Log("get DefaultTTL", res.DefaultTTL)
	assert.Equal(t, int64(600), res.DefaultTTL)
	t.Log("get DefaultEffectiveInterval", res.DefaultEffectiveInterval)
	assert.Equal(t, int64(0), res.DefaultEffectiveInterval)
	t.Log("get Iss", res.Iss)
	assert.Contains(t, res.Iss, res.Algo.String())
}

//TestNewRSASignerWithWrongKeyPath
func TestNewRSASignerWithWrongKeyPath(t *testing.T) {
	func() {
		defer func() {
			if err := recover(); err != nil {
				t.Log("get err", err.(error).Error())
			}
		}()
		NewSigner(WithSignAlgo(
			jwt_pb.EncryptionAlgorithm_RS256),
			WithPemPrivateKeyFromFile("utils/keygener/newkey_rsa.pem1"),
		)
		assert.FailNow(t, "init signer should error")
	}()
}

//TestRSASignerSign 测试RSA签名器签名一个负载
func TestRSASignerSign(t *testing.T) {
	signer, err := NewSigner(
		WithSignAlgo(jwt_pb.EncryptionAlgorithm_RS256),
		WithPemPrivateKeyFromFile("utils/keygener/newkey_rsa.pem"),
	)
	if err != nil {
		assert.FailNow(t, err.Error(), "init signer error")
	}
	payload := testPayLoad{
		A: 1,
		B: "B",
		C: 1.2,
	}
	rsatoken1, err := signer.Sign(payload)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer sign error")
	}

	t.Log("get RefreshToken", rsatoken1.RefreshToken)
	assert.Equal(t, "", rsatoken1.RefreshToken)
	rsatoken2, err := signer.Sign(payload)
	if err != nil {
		assert.FailNow(t, err.Error(), "signer sign error")
	}
	t.Log("get access_token1", rsatoken1.AccessToken)
	t.Log("get access_token2", rsatoken2.AccessToken)
	assert.NotEqual(t, rsatoken1.AccessToken, rsatoken2.AccessToken)
}
