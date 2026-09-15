package gin_middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	jwthelper "github.com/Golang-Tools/jwthelper/v3"
	"github.com/Golang-Tools/jwthelper/v3/jwt_pb"
	"github.com/Golang-Tools/jwthelper/v3/signoptions"
	"github.com/Golang-Tools/jwthelper/v3/verifyoptions"
	"github.com/Golang-Tools/optparams"
)

//fakeVerifier 实现jwthelper.UniversalJwtVerifier的测试替身
type fakeVerifier struct{}

func (fakeVerifier) Meta() (*jwt_pb.VerifierMeta, error) { return &jwt_pb.VerifierMeta{}, nil }

func (fakeVerifier) Verify(token *jwt_pb.Token, payload interface{}, opts ...optparams.Option[verifyoptions.VerifyOptions]) (*jwt_pb.JwtStatus, error) {
	return &jwt_pb.JwtStatus{}, nil
}

//fakeSigner 实现jwthelper.UniversalJwtSigner的测试替身
type fakeSigner struct{}

func (fakeSigner) Meta() (*jwt_pb.SignerMeta, error) { return &jwt_pb.SignerMeta{}, nil }

func (fakeSigner) Sign(payload interface{}, opts ...optparams.Option[signoptions.SignOptions]) (*jwt_pb.Token, error) {
	return &jwt_pb.Token{}, nil
}

//fakeVerifyFunc 构造固定的校验函数
func fakeVerifyFunc(err error) VerifyFunc {
	return func(verifier jwthelper.UniversalJwtVerifier, signer jwthelper.UniversalJwtSigner, token *jwt_pb.Token, ip string, aud []string, selfuid int64, admins ...string) (string, error) {
		if err != nil {
			return "", err
		}
		return "refreshed-token", nil
	}
}

//setupRouter 构造带中间件的测试路由
func setupRouter(mw gin.HandlerFunc, next *bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(mw)
	r.GET("/ping", func(c *gin.Context) {
		*next = true
		c.String(http.StatusOK, "pong")
	})
	return r
}

//TestMiddlewareFinderErrorAborts Finder出错时应直接返回500,不继续执行后续handler
func TestMiddlewareFinderErrorAborts(t *testing.T) {
	nextCalled := false
	finder := func(c *gin.Context) (int64, error) {
		return 0, errors.New("finder error")
	}
	mw := AuthMiddlewareMaker(fakeVerifier{}, fakeSigner{}, fakeVerifyFunc(nil))(
		WithCheckSelf(finder))
	r := setupRouter(mw, &nextCalled)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ping", nil))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.False(t, nextCalled, "Abort 后不应继续执行后续 handler")
}

//TestMiddlewareVerifyErrorAborts 校验失败时应返回403,不继续执行
func TestMiddlewareVerifyErrorAborts(t *testing.T) {
	nextCalled := false
	mw := AuthMiddlewareMaker(fakeVerifier{}, fakeSigner{}, fakeVerifyFunc(errors.New("verify error")))()
	r := setupRouter(mw, &nextCalled)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ping", nil))
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, nextCalled)
}

//TestMiddlewareVerifyOK 校验通过时放行并透出新令牌
func TestMiddlewareVerifyOK(t *testing.T) {
	nextCalled := false
	mw := AuthMiddlewareMaker(fakeVerifier{}, fakeSigner{}, fakeVerifyFunc(nil))()
	r := setupRouter(mw, &nextCalled)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ping", nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, nextCalled)
	assert.Equal(t, "refreshed-token", w.Header().Get("new-access-token"))
}
