# v4.0.0

架构重构版本:核心与特定场景依赖解耦,重依赖能力迁移到 `contrib/*` 独立子模块;领域类型与 pb 解耦;API 大规模现代化(破坏性)。

## 架构变化

+ **核心零重依赖**:`github.com/Golang-Tools/jwthelper/v4` 不再依赖 grpc/protobuf/gin/grpcsdk/schema-entry-go,只保留 jwt/idgener/loggerhelper/optparams/mapset 等轻量依赖
+ **contrib 子模块**(路径不含 /v4,独立版本与 tag,go.mod 带本地 replace 仅供开发联调):
  + `contrib/pb`:proto 定义(`protos/`)与生成码(`jwtpb`/`signerpb`/`verifierpb`)及转换层 `pbconv`;`ResponseStatus` 新增 `error_kind` 字段
  + `contrib/grpcsrv`:grpc 服务端与 CLI(原 `cmd/`),公共骨架抽到 `serverbase`,业务服务端为 `signerserv`/`verifierserv`
  + `contrib/sdk`:grpc 客户端 sdk(原 `sdk/`)
  + `contrib/ginmiddleware`:gin 中间件(原 `gin_middleware/`)

## 破坏性变更

+ 模块路径 `/v3` -> `/v4`,最低 go 版本 1.25 -> 1.26
+ `Sign`/`Verify`/`Meta` 等接口 ctx 化(首参 `context.Context`)
+ 领域类型与 pb 解耦:`jwt_pb.Token`/`jwt_pb.JwtStatus`/加密算法枚举替换为 `jwthelper.Token`/`jwthelper.JwtStatus`/`jwthelper.Algo`(字符串枚举,配 `ParseAlgo`)
+ `JwtStatus.TimeLeft` 语义由"绝对过期时间戳"变更为"剩余秒数",新增 `ExpAt`(绝对过期时间戳,Unix 秒)
+ 选项不再 panic(读取密钥文件失败等错误由构造函数返回);`DefaultSignerOptions`/`DefaultVerifierOptions` 不再导出
+ 错误模型结构化:字段级错误为 `*exceptions.ValidationError`(支持 `errors.Is`),新增 `KindOf`/`SentinelByKind` 稳定分类名;refresh 相关错误消息带字段前缀(如 `refresh.sub : refresh token sub not match`)
+ `gin_middleware` 迁移为 `contrib/ginmiddleware`(包名 `ginmiddleware`);pb 包名 `jwt_pb`->`jwtpb`、`jwtsigner_pb`->`signerpb`、`jwtverifier_pb`->`verifierpb`

## 新特性

+ 可插拔抽口:`SignerKeyProvider`/`VerifierKeyProvider`(动态密钥来源)、`Clock`(时间源,便于测试注入)、`Codec`(编解码,默认标准库 `encoding/json`)、`IDGen`(窄接口,idgener 天然满足)
+ `sdk` 错误映射改为消费 `error_kind`(移除全部字符串匹配实现)
+ `signerproxy`/`verifierproxy`/`ginmiddleware` 支持 `SetLogger` 注入,去除 init 中的全局日志副作用

## bug修复

+ 修复 gRPC 服务端业务错误经由 error 返回导致响应体被丢弃的问题:过期+伴生refresh场景的 `JwtStatus` 客户端此前无法获得;现在业务错误统一经 `ResponseStatus.ErrorKind` 传递,`sdk` 据此映射哨兵错误
+ 修复 CLI `verifier` 子命令因 `default_iss_range` 为 nil slice 无法通过 schema 校验而无法启动的问题(默认初始化为空数组)

## 其它

+ 测试全面适配:接口 ctx 化、核心类型断言、`assert.ErrorIs`;新增 pbconv 往返、错误分类映射往返、sdk 协议(fake 服务端)等测试
+ dockerfile 构建路径改为 `contrib/grpcsrv`,基础镜像升级至 go1.26;镜像 tag 更新为 4.0.0
+ 端到端验证:真实 grpc 服务端 + sdk 完成签名/校验/过期刷新场景

# v3.0.0

模块路径变更为 `github.com/Golang-Tools/jwthelper/v3`,最低 go 版本提升到 1.25。

## 破坏性变更

+ 模块路径由 `/v2` 变更为 `/v3`
+ 最低 go 版本提升到 1.25
+ `sdk.Init` 现在返回 `error`;`sdk.GetLogger` 的返回类型改为 `*slog.Logger`
+ 命令行工具跟随 `schema-entry-go/v4`:长参数名使用小写 json 字段名(如 `--algo_name`),环境变量名规则为`前缀_字段名全大写`

## 依赖迁移

+ `github.com/Golang-Tools/grpcsdk` v0.0.2 -> `github.com/Golang-Tools/grpcsdk/v2` v2.2.0(随 grpc v1.83.2)
+ `github.com/Golang-Tools/loggerhelper/v2` -> `github.com/Golang-Tools/loggerhelper/v4`(slog)
+ `github.com/Golang-Tools/optparams` v0.0.1 -> v1.0.0(GetOption 改为纯函数语义,调用处已适配)
+ `github.com/Golang-Tools/idgener` v0.0.3 -> v1.0.0
+ `github.com/Golang-Tools/schema-entry-go/v2` -> `github.com/Golang-Tools/schema-entry-go/v4`
+ `github.com/golang-jwt/jwt/v4` v4.1.0 -> v4.5.2
+ `github.com/gin-gonic/gin` v1.7.4 -> v1.12.0
+ `github.com/deckarep/golang-set/v2` v2.1.0 -> v2.9.0
+ `github.com/stretchr/testify` v1.7.1 -> v1.12.1
+ `google.golang.org/grpc` v1.46.2 -> v1.83.2、`google.golang.org/protobuf` v1.27.1 -> v1.36.12
+ 移除 `github.com/json-iterator/go`,改用标准库 `encoding/json`

## bug修复

+ 修复 `utils.AlgoStrTOAlgoEnum` 缺少 ES256 分支、EdDSA 因大小写转换无法命中的问题
+ 修复校验器对畸形 claims(exp/aud/jti/iss/sub 类型非法)的断言 panic,现在返回错误而不是崩溃
+ 修复 `sdk` 中响应状态为空时访问 `Status.Message` 的空指针崩溃,以及 `JwtStatus` 判空条件写反的问题
+ 修复伴生 refresh_token 中 `nbf` 被误写为 `nbr` 的问题
+ 修复签名服务端将 `SignRequest.Nbf` 错误应用到 `exp` 的笔误
+ 修复 `gin_middleware` 中 SelfFinder 出错后未终止后续处理的问题;日志与响应的状态码保持一致
+ 修复 `utils/keygener` RSA 密钥长度不足的问题(Go 1.24+ 要求不少于 1024 位),现在固定生成 2048 位
+ 修复 `verifier.Verify` 中正则重复编译的问题(改为包级预编译)

## 其它

+ `signoptions.WithAud/AddAud` 改为保序去重(替换随机顺序实现,输出更确定)
+ `JwtStatus.TimeLeft` 的文档更正为“过期时间戳(Unix 秒)”
+ 补充测试:算法名解析、畸形 claims 回归、gin 中间件、refresh nbf 回归、aud 保序
+ 修正测试中过期于 2021 年的手工 token(改为动态生成),消除时间敏感的用例
+ 全仓库注释格式规范化;删除 `docs/` 静态站产物与 `pmfprc.json`
+ dockerfile 使用 go1.25 基础镜像与 `go install` 方式安装 grpc-health-probe;镜像 tag 更新为 3.0.0

# v2.0.2

## 优化实现

+ 更新`github.com/Golang-Tools/idgener`至v0.0.3,使用枚举替代字符串选择id生成器

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
