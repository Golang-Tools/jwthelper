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
