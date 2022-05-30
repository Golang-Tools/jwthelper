package gin_middleware

import (
	"net/http"
	"strings"

	jwthelper "github.com/Golang-Tools/jwthelper/v2"
	"github.com/Golang-Tools/jwthelper/v2/jwt_pb"
	log "github.com/Golang-Tools/loggerhelper/v2"
	"github.com/Golang-Tools/optparams"
	"github.com/gin-gonic/gin"
)

var logger *log.Log

func init() {
	log.Set(log.WithExtFields(log.Dict{"module": "jwthelper-middlerware"}))
	logger = log.Export()
	log.Set(log.WithExtFields(log.Dict{}))
}

//SelfFinder 找到用户id的函数
type SelfFinder func(*gin.Context) (int64, error)

//option 设置校验选项
type options struct {
	CheckIP    bool
	CheckAdmin []string
	CheckRole  []string
	Finder     SelfFinder
}

var defaultOptions = options{}

//WithCheckIP 校验IP一致性
func WithCheckIP() optparams.Option[options] {
	return optparams.NewFuncOption(func(o *options) {
		o.CheckIP = true
	})
}

//WithCheckAdmin 校验是否是管理员用户,也就是aud是否必须包含其中的至少一个,如果不包含则不能通过
func WithCheckAdmin(rolenames ...string) optparams.Option[options] {
	return optparams.NewFuncOption(func(o *options) {
		o.CheckAdmin = rolenames
	})
}

//WithCheckRole 校验拥有特定权限,如果未设置WithCheckAdmin则会生效,校验aud是否包含其中至少一个
func WithCheckRole(role ...string) optparams.Option[options] {
	return optparams.NewFuncOption(func(o *options) {
		o.CheckRole = role
	})
}

//WithCheckSelf 校验资源是请求者自己的,和WithCheckRole优先级一样,如果未设置WithCheckAdmin则会生效,校验sub是否和finder找到的uid一致
func WithCheckSelf(finder SelfFinder) optparams.Option[options] {
	return optparams.NewFuncOption(func(o *options) {
		o.Finder = finder
	})
}

//MiddlewareFactory 构造auth校验中间件的工厂函数
//没有参数则只校验令牌是否可用
//有WithCheckIP会校验负载中的IP字段是否存在且和当前的请求IP一致
//有WithCheckSuperUser则会校验令牌的aud中是否有superuser
//没有设置WithCheckSuperUser时如果有设置WithCheckRole则会校验令牌的aud中是否包含指定的role字段
//没有设置WithCheckSuperUser时如果有设置WithCheckSelf则会校验令牌的sub是否和用户自己的id一致
//当用户是superuser时则不看是否有role或者id是否一致统一通过
type AuthMiddlewareFactoryFunc func(opts ...optparams.Option[options]) gin.HandlerFunc
type VerifyFunc func(verifier jwthelper.UniversalJwtVerifier, signer jwthelper.UniversalJwtSigner, token *jwt_pb.Token, ip string, aud []string, selfuid int64, admins ...string) (string, error)

//AuthMiddlewareMaker 用于构造`AuthMiddlewareFactoryFunc`的函数
//@Params verifier jwthelper.UniversalJwtVerifier 校验器
//@Params signer jwthelper.UniversalJwtSigner 签名器,用于在有Refresh-Token时刷新token
//@Params verifyfunc VerifyFunc 具体的校验逻辑
func AuthMiddlewareMaker(verifier jwthelper.UniversalJwtVerifier, signer jwthelper.UniversalJwtSigner, verifyfunc VerifyFunc) AuthMiddlewareFactoryFunc {
	return func(opts ...optparams.Option[options]) gin.HandlerFunc {
		dopts := defaultOptions
		optparams.GetOption(&dopts, opts...)
		return func(c *gin.Context) {
			ip := ""
			var selfuid int64 = 0
			admins := []string{}
			if dopts.Finder != nil {
				_selfuid, err := dopts.Finder(c)
				if err != nil {
					logger.Warn("SelfFinder get error", log.Dict{"err": err.Error(), "HttpStatus": http.StatusInternalServerError})
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"Message": err.Error()})
				} else {
					selfuid = _selfuid
				}
			}
			if dopts.CheckIP {
				ip = c.ClientIP()
			}
			if dopts.CheckAdmin != nil && len(dopts.CheckAdmin) > 0 {
				admins = dopts.CheckAdmin
			}
			Authorization := c.GetHeader("Authorization")
			if Authorization == "" {
				Authorization = c.GetHeader("authorization")
			}
			accessToken := strings.ReplaceAll(Authorization, "Bearer ", "")
			refreshtoken := c.GetHeader("Refresh-Token")
			if refreshtoken == "" {
				refreshtoken = c.GetHeader("refresh-token")
			}
			token := jwt_pb.Token{
				RefreshToken: refreshtoken,
				AccessToken:  accessToken,
			}
			newaccesstoken, err := verifyfunc(verifier, signer, &token, ip, dopts.CheckRole, selfuid, admins...)
			if err != nil {
				logger.Warn("verifyfunc get error", log.Dict{"err": err.Error(), "HttpStatus": http.StatusInternalServerError})
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"Message": err.Error()})
			} else {
				c.Header("new-access-token", newaccesstoken)
				c.Next()
			}
		}
	}
}
