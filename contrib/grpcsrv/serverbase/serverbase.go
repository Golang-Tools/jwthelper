// grpc服务端公共骨架:公共配置快照、性能/TLS选项构造与启动流程。
// 由于配置解析框架(schema-entry-go)要求可配置字段平铺在业务结构体上,
// 各业务服务端在自己的结构体上平铺公共配置字段,再通过Options()方法
// 映射为serverbase.Options传入本包函数。
package serverbase

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	log "github.com/Golang-Tools/loggerhelper/v4"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	xdscreds "google.golang.org/grpc/credentials/xds"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/xds"
)

// RegisterFunc 向grpc服务注册业务实现的方法
type RegisterFunc func(gs grpc.ServiceRegistrar)

// Options grpc服务端公共配置的值快照,与业务服务端平铺的公共字段一一对应
type Options struct {
	App_Name    string
	App_Version string
	Address     string
	Log_Level   string

	// 性能设置
	Max_Recv_Msg_Size                           int
	Max_Send_Msg_Size                           int
	Initial_Window_Size                         int
	Initial_Conn_Window_Size                    int
	Max_Concurrent_Streams                      int
	Max_Connection_Idle                         int
	Max_Connection_Age                          int
	Max_Connection_Age_Grace                    int
	Keepalive_Time                              int
	Keepalive_Timeout                           int
	Keepalive_Enforcement_Min_Time              int
	Keepalive_Enforcement_Permit_Without_Stream bool

	// TLS设置
	Server_Cert_Path string
	Server_Key_Path  string
	Ca_Cert_Path     string
	Client_Crl_Path  string

	// 使用XDS
	XDS       bool
	XDS_CREDS bool
}

// InitLogger 按配置初始化全局日志并输出服务配置
func InitLogger(o *Options, config any) {
	log.Set(log.WithLevel(o.Log_Level),
		log.AddExtField("app_name", o.App_Name),
		log.AddExtField("app_version", o.App_Version),
	)
	log.Info("grpc服务获得参数", log.Dict{"ServiceConfig": config})
}

// PerformanceOpts 依据性能配置在传入opts基础上追加构造grpc.ServerOption
func PerformanceOpts(o *Options, opts []grpc.ServerOption) []grpc.ServerOption {
	if opts == nil {
		opts = []grpc.ServerOption{}
	}

	if o.Max_Recv_Msg_Size != 0 {
		opts = append(opts, grpc.MaxRecvMsgSize(o.Max_Recv_Msg_Size))
	}
	if o.Max_Send_Msg_Size != 0 {
		opts = append(opts, grpc.MaxSendMsgSize(o.Max_Send_Msg_Size))
	}
	if o.Initial_Window_Size != 0 {
		opts = append(opts, grpc.InitialWindowSize(int32(o.Initial_Window_Size)))
	}
	if o.Initial_Conn_Window_Size != 0 {
		opts = append(opts, grpc.InitialConnWindowSize(int32(o.Initial_Conn_Window_Size)))
	}
	if o.Max_Concurrent_Streams != 0 {
		opts = append(opts, grpc.MaxConcurrentStreams(uint32(o.Max_Concurrent_Streams)))
	}
	if o.Max_Connection_Idle != 0 || o.Max_Connection_Age != 0 || o.Max_Connection_Age_Grace != 0 || o.Keepalive_Time != 0 || o.Keepalive_Timeout != 0 {
		kasp := keepalive.ServerParameters{
			MaxConnectionIdle:     time.Duration(o.Max_Connection_Idle) * time.Second,
			MaxConnectionAge:      time.Duration(o.Max_Connection_Age) * time.Second,
			MaxConnectionAgeGrace: time.Duration(o.Max_Connection_Age_Grace) * time.Second,
			Time:                  time.Duration(o.Keepalive_Time) * time.Second,
			Timeout:               time.Duration(o.Keepalive_Timeout) * time.Second,
		}
		opts = append(opts, grpc.KeepaliveParams(kasp))
	}

	if o.Keepalive_Enforcement_Min_Time != 0 || o.Keepalive_Enforcement_Permit_Without_Stream {
		kaep := keepalive.EnforcementPolicy{
			MinTime:             time.Duration(o.Keepalive_Enforcement_Min_Time) * time.Second,
			PermitWithoutStream: o.Keepalive_Enforcement_Permit_Without_Stream,
		}
		opts = append(opts, grpc.KeepaliveEnforcementPolicy(kaep))
	}
	return opts
}

// TLSOpts 依据TLS配置在传入opts基础上追加构造grpc.ServerOption
func TLSOpts(o *Options, opts []grpc.ServerOption) []grpc.ServerOption {
	if opts == nil {
		opts = []grpc.ServerOption{}
	}
	if o.Ca_Cert_Path != "" {
		cert, err := tls.LoadX509KeyPair(o.Server_Cert_Path, o.Server_Key_Path)
		if err != nil {
			log.Error("read serv pem file error:", log.Dict{"err": err.Error(), "Cert_path": o.Server_Cert_Path, "Key_Path": o.Server_Key_Path})
			os.Exit(2)
		}
		capool := x509.NewCertPool()
		caCrt, err := os.ReadFile(o.Ca_Cert_Path)
		if err != nil {
			log.Error("read ca pem file error:", log.Dict{"err": err.Error(), "path": o.Ca_Cert_Path})
			os.Exit(2)
		}
		capool.AppendCertsFromPEM(caCrt)
		tlsconf := &tls.Config{
			RootCAs:      capool,
			ClientAuth:   tls.RequireAndVerifyClientCert, // 检验客户端证书
			Certificates: []tls.Certificate{cert},
		}
		if o.Client_Crl_Path != "" {
			clipool := x509.NewCertPool()
			cliCrt, err := os.ReadFile(o.Client_Crl_Path)
			if err != nil {
				log.Error("read pem file error:", log.Dict{"err": err.Error(), "path": o.Client_Crl_Path})
				os.Exit(2)
			}
			clipool.AppendCertsFromPEM(cliCrt)
			tlsconf.ClientCAs = clipool
		}
		creds := credentials.NewTLS(tlsconf)
		opts = append(opts, grpc.Creds(creds))
	} else {
		creds, err := credentials.NewServerTLSFromFile(o.Server_Cert_Path, o.Server_Key_Path)
		if err != nil {
			log.Error("Failed to Listen as a TLS Server", log.Dict{"error": err.Error()})
			os.Exit(2)
		}
		opts = append(opts, grpc.Creds(creds))
	}
	log.Info("server will start use TLS")
	return opts
}

// RunServer 启动服务,register为业务实现注册函数
func RunServer(o *Options, register RegisterFunc) {
	lis, err := net.Listen("tcp", o.Address)
	if err != nil {
		log.Error("Failed to Listen", log.Dict{"error": err.Error(), "address": o.Address})
		os.Exit(1)
	}
	opts := PerformanceOpts(o, nil)
	if o.XDS {
		// 注意目前的XDS模式不支持反射,且健康监测不能和服务主体在同一个接口(现在默认为服务端口号+1)
		creds := insecure.NewCredentials()
		var err error
		if o.XDS_CREDS {
			creds, err = xdscreds.NewServerCredentials(xdscreds.ServerOptions{FallbackCreds: insecure.NewCredentials()})
		}
		if err != nil {
			log.Error("failed to create server-side xDS credentials", log.Dict{"error": err.Error()})
			os.Exit(2)
		}
		opts = append(opts, grpc.Creds(creds))
		log.Info("server will start use XDS_CREDS")
		gs, err := xds.NewGRPCServer(opts...)
		if err != nil {
			log.Error("failed to create xDS server", log.Dict{"error": err.Error()})
			os.Exit(2)
		}
		defer gs.Stop()
		register(gs)
		// 注册健康检查
		hostinfo := strings.Split(o.Address, ":")
		if len(hostinfo) != 2 {
			log.Error("address format not ok", log.Dict{"address": o.Address})
			os.Exit(2)
		}
		port, err := strconv.Atoi(hostinfo[1])
		if err != nil {
			log.Error("address port not int", log.Dict{"address": o.Address})
			os.Exit(2)
		}
		healthaddress := fmt.Sprintf("%s:%d", hostinfo[0], port+1)
		healthLis, err := net.Listen("tcp4", healthaddress)
		if err != nil {
			log.Error("Health Service Failed to Listen", log.Dict{"error": err.Error(), "address": healthaddress})
			os.Exit(1)
		}
		healthServer := grpc.NewServer()
		healthservice := health.NewServer()
		healthservice.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
		healthpb.RegisterHealthServer(healthServer, healthservice)
		// 无法注册反射

		// 启动服务
		log.Info("Server Start", log.Dict{"address": o.Address, "health_service_addres": healthaddress})
		go func() {
			err := gs.Serve(lis)
			if err != nil {
				log.Error("Failed to Serve", log.Dict{"error": err})
				os.Exit(1)
			}
		}()
		go healthServer.Serve(healthLis)
		// 等待中断信号以优雅地关闭服务器(设置 3 秒的超时时间)
		quit := make(chan os.Signal, 3)
		signal.Notify(quit, os.Interrupt)
		<-quit
		log.Info("Shutdown Server ...")
		gs.GracefulStop()
		healthServer.GracefulStop()
	} else {
		if o.Server_Cert_Path != "" && o.Server_Key_Path != "" {
			opts = TLSOpts(o, opts)
		}
		gs := grpc.NewServer(opts...)
		defer gs.Stop()
		// 注册健康检查
		healthservice := health.NewServer()
		healthservice.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
		healthpb.RegisterHealthServer(gs, healthservice)

		// 注册反射
		reflection.Register(gs)
		// 注册服务
		register(gs)

		// 启动服务
		log.Info("Server Start", log.Dict{"address": o.Address})
		err = gs.Serve(lis)
		if err != nil {
			log.Error("Failed to Serve", log.Dict{"error": err})
			os.Exit(1)
		}
	}
}
