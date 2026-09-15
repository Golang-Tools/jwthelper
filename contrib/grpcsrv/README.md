# jwthelper grpcsrv

jwthelper 的服务端 CLI 与 grpc 服务实现,提供三个子命令:

- `createkey`:生成 rsa/ecdsa/ed25519 公私钥对
- `signer`:启动 jwt 签名 grpc 服务
- `verifier`:启动 jwt 校验 grpc 服务

公共的 grpc 服务端骨架(性能/TLS/keepalive/xDS/健康检查)在 `serverbase` 中,
各业务服务端(`signerserv`/`verifierserv`)通过内嵌 `serverbase.ServerBase` 复用。

## 构建

```bash
go build -o jwthelper .
```

## 用法

```bash
./jwthelper createkey|signer|verifier [options]
```
