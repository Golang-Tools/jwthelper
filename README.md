# jwthelper

jwt标准过于简单,往往在生产上并不是简单使用,本项目基于[我的这篇博文](https://blog.hszofficial.site/introduce/2021/05/25/%E7%BD%91%E7%BB%9C%E8%BA%AB%E4%BB%BD%E8%AE%A4%E8%AF%81/).在可以进行简单签名简单验签的同时也支持使用伴生的刷新jwt做自动刷新令牌.

本项目本质上只是`github.com/golang-jwt/jwt/v4`的封装,只是提供了相对更友好的接口和一些专用模式封装而已

## 特性

+ 有`Signer`类用于作为签名器
+ 有`Verifier`类用于做签名校验器
+ 提供`Meta`函数用于查看签名器和签名校验器的元信息
+ 提供接口`UniversalJwtSigner`和`UniversalJwtVerifier`方便抽象
+ 支持主流的`RS256`,`RS384`,`RS512`,`ES256`,`ES384`,`ES512`,`HS256`,`HS384`,`HS512`9种算法用于签名和校验
+ 支持构造jwt时同时创建伴生的刷新jwt,同时也支持校验这种token
+ 使用类似grpc的函数接口风格构造可选参数,提供丰富的可选项

## 用法

> 简单签名和验签

    ```golang
    //签名,默认使用HS256算法,jti使用uuid4生成可以配置改为sonyflake或者自己实现一个满足接口`utils/idgener.IDGen`的id生成器
    signer, err := NewSigner()
    if err != nil {
        return err
    }
    payload := testPayLoad{
        A: 1,
        B: "B",
        C: 1.2,
    }
    //签名时可以添加sub等信息
    token, err := signer.Sign(payload, signoptions.WithSub("test"),signoptions.WithAud("testaud"))

    //验签,默认使用HS256算法
    verifier, err := NewVerifier(WithDefaultAUD("testaud"), WithDefaultISSRange(signer.Meta().Iss))
    if err != nil {
        return err
    }
    payload1 := testPayLoad{}
    //可以校验iss,aud和sub等
    jti, timeleft, err := verifier.Verify(token, &payload1,veriffyoptions.WithSUBMustBe(test))
    if err == nil {
        return err
    }
    ```
> 带fresh_token的签名和对应验签

    ```golang
    //签名
    signer, err := NewSigner()
    if err != nil {
        return err
    }
    payload := testPayLoad{
        A: 1,
        B: "B",
        C: 1.2,
    }
    //签名的不同之处只是增加了选项`signoptions.WithRefreshTTL`
    token, err := signer.Sign(payload, signoptions.WithSub("test"),signoptions.WithAud("testaud"),signoptions.WithRefreshTTL(time.Hour*24))

    //验签
    verifier, err := NewVerifier(WithDefaultAUD("testaud"), WithDefaultISSRange(signer.Meta().Iss))
    if err != nil {
        return err
    }
    payload1 := testPayLoad{}
    //会根据token中`RefreshToken`字段是否为空值来确定是简单jwt还是带伴生fresh_tokende的
    jti, timeleft, err := verifier.Verify(token, &payload1,veriffyoptions.WithSUBMustBe(test))
    if err == nil {
        return err
    }
    ```

更多的方法可选项可以看文档

## 附加工具

+ `utils/idgener`模块提供两个`IDGen`接口的实现分别是
    + `UUID4Gen`,使用uuid4生成全局唯一id
    + `SonyflakeGen`,使用`github.com/sony/sonyflake`生成全局唯一id

+ `utils/machineid`模块用于通过本机的第一张网卡的ip生成机器id
+ `utils/keygener`模块用于生成随机的公私钥对
+ `proxy`用于代理满足`UniversalJwtSigner`和`UniversalJwtVerifier`接口的对象