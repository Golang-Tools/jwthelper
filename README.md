# jwthelper V3

jwt标准过于简单,往往在生产上并不是简单使用,本项目基于[我的这篇博文](https://blog.hszofficial.site/introduce/2021/05/25/%E7%BD%91%E7%BB%9C%E8%BA%AB%E4%BB%BD%E8%AE%A4%E8%AF%81/).在可以进行简单签名简单验签的同时也支持使用伴生的刷新jwt做自动刷新令牌.

本项目本质上只是`github.com/golang-jwt/jwt/v4`的封装,只是提供了相对更友好的接口和一些专用模式封装而已

V3版本面向go 1.25+,模块路径为`github.com/Golang-Tools/jwthelper/v3`;旧版本请使用[V2](https://github.com/Golang-Tools/jwthelper/tree/master)(module路径带`/v2`,不再演进)

## 特性

+ 有`Signer`类用于作为签名器
+ 有`Verifier`类用于做签名校验器
+ 提供`Meta`函数用于查看签名器和签名校验器的元信息
+ 提供接口`UniversalJwtSigner`和`UniversalJwtVerifier`方便抽象
+ 支持主流的`RS256`,`RS384`,`RS512`,`ES256`,`ES384`,`ES512`,`HS256`,`HS384`,`HS512`与`EdDSA`算法用于签名和校验
+ 支持构造jwt时同时创建伴生的刷新jwt,同时也支持校验这种token
+ 使用类似grpc的函数接口风格构造可选参数,提供丰富的可选项
+ 日志基于`github.com/Golang-Tools/loggerhelper/v4`(标准库`log/slog`)

## 用法

> 简单签名和验签

```golang
//签名,默认使用HS256算法,jti使用uuid4生成,可以配置改为sonyflake或者自己实现一个满足接口`idgener.IDGenInterface`的id生成器
signer, err := jwthelper.NewSigner()
if err != nil {
    return err
}
payload := testPayLoad{
    A: 1,
    B: "B",
    C: 1.2,
}
//签名时可以添加sub/aud等信息
token, err := signer.Sign(payload,
    signoptions.WithSub("test"),
    signoptions.WithAud("testaud"),
    signoptions.WithTTL(time.Hour),
)

//验签,默认使用HS256算法
verifier, err := jwthelper.NewVerifier(jwthelper.WithDefaultAUD("testaud"))
if err != nil {
    return err
}
payload1 := testPayLoad{}
//可以校验iss,aud和sub等
status, err := verifier.Verify(token, &payload1, verifyoptions.WithSUBMustBe("test"))
//status为`*jwt_pb.JwtStatus`,包含Jti/Sub/Iss/Aud与TimeLeft(过期时间戳,Unix秒)
```

> 带refresh_token的签名和对应验签

```golang
//签名,不同之处只是增加了选项`signoptions.WithRefreshTTL`
token, err := signer.Sign(payload,
    signoptions.WithSub("test"),
    signoptions.WithAud("testaud"),
    signoptions.WithRefreshTTL(time.Hour*24),
)

//验签,会根据token中`RefreshToken`字段是否为空值来确定是简单jwt还是带伴生refresh_token的
payload1 := testPayLoad{}
status, err := verifier.Verify(token, &payload1)
//当access_token过期但伴生的refresh_token没有过期时:
//+ 返回的error为`exceptions.ErrValidationErrorExpired`
//+ status依然会被填充,TimeLeft为refresh_token的过期时间戳
```

更多的方法可选项可以看文档

## 附加工具

`cmd`目录用于构造jwthelper的命令行工具(基于`github.com/Golang-Tools/schema-entry-go/v4`,参数支持命令行/环境变量/配置文件三种来源),这个工具提供如下工具:

+ `jwthelper createkey`用于创建公私钥对
+ `jwthelper signer`,用于启动一个基于grpc的签名器服务端,具体接口请查看`pbschema/jwtsigner.proto`
+ `jwthelper verifier`,用于启动一个基于grpc的签名校验器服务端,具体接口请查看`pbschema/jwtverifier.proto`

用法示例:

```bash
# 查看帮助
jwthelper signer --help

# 命令行参数启动签名服务
jwthelper signer --algo_name HS256 --key_path ./key.txt --address 0.0.0.0:5000

# 环境变量(命名规则为`前缀_字段名全大写`,前缀为节点路径大写)启动
export JWTHELPER_SIGNER_ALGO_NAME=HS256
export JWTHELPER_SIGNER_KEY_PATH=./key.txt
jwthelper signer
```

这个工具也可以使用docker使用,托管在dockerhub上的`hsz1273327/jwthelper`下,编排示例见`docker-compose.yml`

## 附加模块

+ `utils/keygener`模块用于生成随机的公私钥对
+ `signerproxy`和`verifierproxy`用于代理满足`UniversalJwtSigner`和`UniversalJwtVerifier`接口的对象
+ `sdk`用于对接`cmd`中提供的grpc,使用它构造的对象也分别满足`UniversalJwtSigner`和`UniversalJwtVerifier`接口
+ `gin_middleware`gin的校验模块工具

## 从V2迁移

+ 修改import路径:`github.com/Golang-Tools/jwthelper/v2` -> `github.com/Golang-Tools/jwthelper/v3`
+ 最低go版本提升到1.25
+ `sdk.Init`现在返回`error`;`sdk.GetLogger`返回`*slog.Logger`
+ 命令行长参数由字段名改为小写json字段名(如`--algo_name`);环境变量名规则为`前缀_字段名全大写`
+ 校验器遇到畸形claims(字段类型非法)时返回错误而不是panic
+ 伴生refresh_token中的`nbf`键拼写修正(此前误写为`nbr`)
