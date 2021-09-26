# jwtverifier

jwt签名的验证器,支持对称和不对成加密

调用接口`Asymmetric.Verify(tokenstring string) (map[string]interface{}, error)`校验并获得非对称加密的jwttoken;

调用接口`Symmetric.Verify(tokenstring string) (map[string]interface{}, error)`校验并获得对称加密的jwttoken;