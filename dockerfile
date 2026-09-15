# 构造可执行文件
FROM --platform=$TARGETPLATFORM golang:1.25-alpine as build_bin
ENV GOPROXY=https://goproxy.cn,https://goproxy.io,direct
# 停用cgo
ENV CGO_ENABLED=0
WORKDIR /code
COPY go.mod /code/go.mod
COPY go.sum /code/go.sum
# 添加源文件
COPY cmd /code/cmd
COPY exceptions /code/exceptions
COPY jwt_pb /code/jwt_pb
COPY jwtsigner_pb /code/jwtsigner_pb
COPY jwtverifier_pb /code/jwtverifier_pb
COPY signoptions /code/signoptions
COPY utils /code/utils
COPY verifyoptions /code/verifyoptions
COPY jwthelper.go /code/jwthelper.go
COPY signer.go /code/signer.go
COPY signeroptions.go /code/signeroptions.go
COPY universal.go /code/universal.go
COPY verifier.go /code/verifier.go
COPY verifieroptions.go /code/verifieroptions.go
RUN go build -ldflags "-s -w" -o jwthelper-go cmd/main.go

# 使用upx压缩可执行文件
FROM --platform=$TARGETPLATFORM alpine:3.22 as upx
WORKDIR /code
# 安装upx
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
RUN apk update && apk add --no-cache upx && rm -rf /var/cache/apk/*
COPY --from=build_bin /code/jwthelper-go .
RUN upx --best --lzma -o jwthelper jwthelper-go

# 编译获得grpc-health-probe
FROM --platform=$TARGETPLATFORM golang:1.25-bookworm as build_grpc-health-probe
ENV GOPROXY=https://goproxy.cn,https://goproxy.io,direct
# 停用cgo
ENV CGO_ENABLED=0
# 安装grpc-health-probe
RUN go install github.com/grpc-ecosystem/grpc-health-probe@latest

# 使用压缩过的可执行文件构造镜像
FROM --platform=$TARGETPLATFORM scratch as build_img
# 打包镜像
COPY --from=build_grpc-health-probe /go/bin/grpc-health-probe .
COPY --from=upx /code/jwthelper .
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 CMD [ "/grpc-health-probe","-addr=:5000" ]
ENTRYPOINT [ "/jwthelper"]