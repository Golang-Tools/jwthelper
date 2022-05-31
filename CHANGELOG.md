# v2.0.1

+ 使用`github.com/Golang-Tools/grpcsdk`重构了sdk
+ 使用`github.com/Golang-Tools/optparams`重构了所有可选参数
+ 抽离id创建工具idgener和相关的获取本机id的代码为独立项目`github.com/Golang-Tools/idgener`
+ 使用`github.com/deckarep/golang-set/v2`替代原本的set实现

# v2.0.0

更新支持 go 1.18+

# v0.0.5

## 修改实现

+ 修改`gin_middleware`的实现,现在重新刷新的`access_token`将放在`new-access-token`中

## bug修复

+ 修复`gin_middleware`无法返回错误信息的问题
+ 修复`gin_middleware`对http2的兼容性问题,现在小写的对应headers也可以被识别

## 接口变化

+ `gin_middleware`的`AuthMiddlewareMaker`函数新增可用参数`WithLogger`,当校验不通过时会打印信息

# v0.0.4

## 接口变化

+ `UniversalJwtVerify`接口关于aud的参数改为集合计算`verifyoptions.WithAUDMustHas`,`verifyoptions.WithAUDMustHasAny`,`verifyoptions.WithAUDMustNotHas`而不再是单纯检验某个aud是否在其中

## 依赖更新

+ `github.com/Golang-Tools/schema-entry-go`->`v0.0.7`

## 增加模块

+ `gin_middleware`gin的校验模块工具

# v0.0.3

## 接口变化

+ `UniversalJwtVerify`接口变化,其对应实现也一起变化,现在`UniversalJwtVerify`返回`*jwt_pb.JwtStatus`,用于标识jwt的状态信息

# v0.0.2

## bug修复

修复了`UniversalJwtVerifier`的声明错误

# v0.0.1

项目创建,包含组件:

+ `github.com/Golang-Tools/jwthelper`提供签名器和签名解析器模块
+ `github.com/Golang-Tools/jwthelper/utils/idgener`模块提供两个`IDGen`接口的实现分别是
    + `UUID4Gen`,使用uuid4生成全局唯一id
    + `SonyflakeGen`,使用`github.com/sony/sonyflake`生成全局唯一id

+ `github.com/Golang-Tools/jwthelper/utils/machineid`模块用于通过本机的第一张网卡的ip生成机器id
+ `github.com/Golang-Tools/jwthelper/utils/keygener`模块用于生成随机的公私钥对
+ `github.com/Golang-Tools/jwthelper/cmd`提供命令行工具用于
    + 创建公私钥对
    + 启动远程的签名器grpc
    + 启动远程的签名校验器grpc

+ `github.com/Golang-Tools/jwthelper/sdk`用于对接`cmd`中提供的grpc,使用它构造的对象也分别满足`UniversalJwtSigner`和`UniversalJwtVerifier`接口
+ `github.com/Golang-Tools/jwthelper/proxy`用于代理满足`UniversalJwtSigner`和`UniversalJwtVerifier`接口的对象
