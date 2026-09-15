# jwthelper V4

jwt标准过于简单,往往在生产上并不是简单使用,本项目基于[我的这篇博文](https://blog.hszofficial.site/introduce/2021/05/25/%E7%BD%91%E7%BB%9C%E8%BA%AB%E4%BB%BD%E8%AE%A4%E8%AF%81/).在可以进行简单签名简单验签的同时也支持使用伴生的刷新jwt做自动刷新令牌.

本项目本质上只是`github.com/golang-jwt/jwt/v4`的封装,只是提供了相对更友好的接口和一些专用模式封装而已

V4版本面向go 1.26+,模块路径为`github.com/Golang-Tools/jwthelper/v4`,**核心保持零重依赖**(不引入grpc/gin/protobuf);与特定场景相关的重依赖能力(grpc服务端、客户端sdk、gin中间件、pb定义)拆分为独立子模块,放在`contrib/`下按需引入。旧版本请使用[V3](https://github.com/Golang-Tools/jwthelper/tree/v3)(module路径带`/v3`,不再演进)

## 特性(核心)

+ 有`Signer`类用于作为签名器,`Verifier`类用于做签名校验器
+ 有`Meta`函数用于查看签名器和签名校验器的元信息
+ 领域类型(`Algo`/`Token`/`SignerMeta`/`VerifierMeta`/`JwtStatus`)与传输层(pb)完全解耦
+ 主要接口均接受`context.Context`,便于超时/取消传播,配合密钥提供者可对接动态密钥来源
+ 可插拔抽口:`SignerKeyProvider`/`VerifierKeyProvider`(动态密钥)、`Clock`(时间源,便于测试注入)、`Codec`(编解码,默认标准库`encoding/json`)、`IDGen`(窄接口)
+ 提供接口`UniversalJwtSigner`和`UniversalJwtVerifier`方便抽象
+ 支持主流的`RS256`,`RS384`,`RS512`,`ES256`,`ES384`,`ES512`,`HS256`,`HS384`,`HS512`与`EdDSA`算法用于签名和校验
+ 支持构造jwt时同时创建伴生的刷新jwt,同时也支持校验这种token
+ 结构化错误:字段级错误为`*exceptions.ValidationError`(支持`errors.Is`),并提供`exceptions.KindOf`/`exceptions.SentinelByKind`稳定错误分类(供传输层映射错误码)
+ 使用类似grpc的函数接口风格构造可选参数,提供丰富的可选项;读取密钥文件失败等错误不再panic,由构造函数返回
+ 日志基于`github.com/Golang-Tools/loggerhelper/v4`(标准库`log/slog`),无全局副作用

## 用法

> 简单签名和验签

```golang
//签名,默认使用HS256算法,jti使用uuid4生成,可以配置改为sonyflake或者自己实现一个满足接口`jwthelper.IDGen`的id生成器
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
token, err := signer.Sign(context.Background(), payload,
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
status, err := verifier.Verify(context.Background(), token, &payload1, verifyoptions.WithSUBMustBe("test"))
//status为`*jwthelper.JwtStatus`,包含Jti/Sub/Iss/Aud,
//以及ExpAt(绝对过期时间戳,Unix秒)与TimeLeft(剩余秒数)
```

> 带refresh_token的签名和对应验签

```golang
//签名,不同之处只是增加了选项`signoptions.WithRefreshTTL`
token, err := signer.Sign(context.Background(), payload,
    signoptions.WithSub("test"),
    signoptions.WithAud("testaud"),
    signoptions.WithRefreshTTL(time.Hour*24),
)

//验签,会根据token中`RefreshToken`字段是否为空值来确定是简单jwt还是带伴生refresh_token的
payload1 := testPayLoad{}
status, err := verifier.Verify(context.Background(), token, &payload1)
//当access_token过期但伴生的refresh_token没有过期时:
//+ 返回的error为`exceptions.ErrValidationErrorExpired`(可用`errors.Is`判断)
//+ status依然会被填充,TimeLeft为refresh_token的剩余秒数
```

> 注入抽口(动态密钥/时间源/编解码)

```golang
signer, err := jwthelper.NewSigner(
    jwthelper.WithSignKeyProvider(myProvider), // 实现 `SignerKeyProvider` 接口,支持动态/轮换密钥
    jwthelper.WithSignClock(myClock),          // 实现 `Clock` 接口,便于测试注入
    jwthelper.WithSignCodec(myCodec),          // 实现 `Codec` 接口,替换默认的encoding/json
)
```

更多的方法可选项可以看文档

## 附加模块(contrib)

V4将重依赖能力拆分到独立子模块(模块路径不含`/v4`,各自独立打tag),按需引入:

| 模块 | 模块路径 | 说明 |
| --- | --- | --- |
| pb | `github.com/Golang-Tools/jwthelper/contrib/pb` | proto定义、生成码(`jwtpb`/`signerpb`/`verifierpb`)与核心类型转换层`pbconv` |
| grpcsrv | `github.com/Golang-Tools/jwthelper/contrib/grpcsrv` | grpc签名/校验服务端与命令行工具(基于`schema-entry-go/v4`) |
| sdk | `github.com/Golang-Tools/jwthelper/contrib/sdk` | grpc客户端sdk,使用它构造的对象分别满足`UniversalJwtSigner`和`UniversalJwtVerifier`接口 |
| ginmiddleware | `github.com/Golang-Tools/jwthelper/contrib/ginmiddleware` | gin的校验模块工具 |

> 各子模块的`go.mod`中带有指向本地核心的`replace`(仅开发联调用,消费方引入时会被忽略,使用子模块正式版本即可)。

核心内还提供:

+ `utils/keygener`模块用于生成随机的公私钥对
+ `signerproxy`和`verifierproxy`用于代理满足`UniversalJwtSigner`和`UniversalJwtVerifier`接口的对象

### grpcsrv 命令行工具

`contrib/grpcsrv`提供如下工具:

+ `jwthelper createkey`用于创建公私钥对
+ `jwthelper signer`,用于启动一个基于grpc的签名器服务端,具体接口请查看`contrib/pb/protos/jwtsigner.proto`
+ `jwthelper verifier`,用于启动一个基于grpc的签名校验器服务端,具体接口请查看`contrib/pb/protos/jwtverifier.proto`

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

## 从V3迁移

+ 修改import路径:`github.com/Golang-Tools/jwthelper/v3` -> `github.com/Golang-Tools/jwthelper/v4`;最低go版本提升到1.26
+ 核心接口ctx化:`Sign`/`Verify`/`Meta`等方法现在接受`context.Context`作为第一个参数
+ 领域类型替换pb类型:`jwt_pb.Token`/`jwt_pb.JwtStatus`等替换为`jwthelper.Token`/`jwthelper.JwtStatus`;加密算法枚举替换为`jwthelper.Algo`(字符串枚举)与`jwthelper.ParseAlgo`
+ `JwtStatus.TimeLeft`语义变更:现在为剩余秒数(此前为绝对过期时间戳),绝对过期时间戳可用新增的`ExpAt`字段
+ 选项不再panic:`WithSignSecretKeyFromFile`/`WithPemPrivateKeyFromFile`等读取失败时错误由构造函数返回
+ `DefaultSignerOptions`/`DefaultVerifierOptions`不再导出(默认值已收口)
+ 错误模型结构化:refresh相关校验错误的`Error()`消息带字段前缀(如`refresh.sub : ...`);建议改用`errors.Is`/`exceptions.KindOf`判断
+ pb、命令行工具、sdk、gin中间件迁移到`contrib/*`子模块;pb包名`jwt_pb`->`jwtpb`、`jwtsigner_pb`->`signerpb`、`jwtverifier_pb`->`verifierpb`
+ grpc服务端业务错误不再通过gRPC error返回(该方式会丢失响应体),统一经`ResponseStatus.ErrorKind`传递,`sdk`据此映射哨兵错误
+ `gin_middleware`迁移为`contrib/ginmiddleware`,包名`ginmiddleware`
