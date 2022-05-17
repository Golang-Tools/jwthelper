package jwtverifier_serv

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/Golang-Tools/jwthelper/jwt_pb"
	"github.com/Golang-Tools/jwthelper/jwtverifier_pb"
	"github.com/Golang-Tools/jwthelper/utils"
	jwthelper "github.com/Golang-Tools/jwthelper/v2"

	log "github.com/Golang-Tools/loggerhelper/v2"

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

//Server grpc的服务器结构体
//服务集成了如下特性:
//设置收发最大消息长度
//健康检测
//gzip做消息压缩
//接口反射
//TLS支持
//keep alive 支持
type Server struct {
	App_Name    string `json:"app_name,omitempty" jsonschema:"required,description=服务名,default=jwthelper_verifierrpc"`
	App_Version string `json:"app_version,omitempty" jsonschema:"description=服务版本,default=2.0.0"`
	Address     string `json:"address,omitempty" jsonschema:"required,description=服务的主机和端口,default=0.0.0.0:5000"`
	Log_Level   string `json:"log_level,omitempty" jsonschema:"required,description=项目的log等级,enum=TRACE,enum=DEBUG,enum=INFO,enum=WARN,enum=ERROR,default=DEBUG"`

	// 性能设置
	Max_Recv_Msg_Size                           int  `json:"max_recv_msg_size,omitempty" jsonschema:"description=允许接收的最大消息长度"`
	Max_Send_Msg_Size                           int  `json:"max_send_msg_size,omitempty" jsonschema:"description=允许发送的最大消息长度"`
	Initial_Window_Size                         int  `json:"initial_window_size,omitempty" jsonschema:"description=基于Stream的滑动窗口大小"`
	Initial_Conn_Window_Size                    int  `json:"initial_conn_window_size,omitempty" jsonschema:"description=基于Connection的滑动窗口大小"`
	Max_Concurrent_Streams                      int  `json:"max_concurrent_streams,omitempty" jsonschema:"description=一个连接中最大并发Stream数"`
	Max_Connection_Idle                         int  `json:"max_connection_idle,omitempty" jsonschema:"description=客户端连接的最大空闲时长"`
	Max_Connection_Age                          int  `json:"max_connection_age,omitempty" jsonschema:"description=如果连接存活超过n则发送goaway"`
	Max_Connection_Age_Grace                    int  `json:"max_connection_age_grace,omitempty" jsonschema:"description=强制关闭连接之前允许等待的rpc在n秒内完成"`
	Keepalive_Time                              int  `json:"keepalive_time,omitempty" jsonschema:"description=空闲连接每隔n秒ping一次客户端已确保连接存活"`
	Keepalive_Timeout                           int  `json:"keepalive_timeout,omitempty" jsonschema:"description=ping时长超过n则认为连接已死"`
	Keepalive_Enforcement_Min_Time              int  `json:"keepalive_enforement_min_time,omitempty" jsonschema:"description=如果客户端超过每n秒ping一次则终止连接"`
	Keepalive_Enforcement_Permit_Without_Stream bool `json:"keepalive_enforement_permit_without_stream,omitempty" jsonschema:"description=即使没有活动流也允许ping"`

	//TLS设置
	Server_Cert_Path string `json:"server_cert_path,omitempty" jsonschema:"description=使用TLS时服务端的证书位置"`
	Server_Key_Path  string `json:"server_key_path,omitempty" jsonschema:"description=使用TLS时服务端证书的私钥位置"`
	Ca_Cert_Path     string `json:"ca_cert_path,omitempty" jsonschema:"description=使用TLS时根整数位置"`
	Client_Crl_Path  string `json:"client_crl_path,omitempty" jsonschema:"description=客户端证书黑名单位置"`

	//使用XDS
	XDS       bool `json:"xds,omitempty" jsonschema:"description=是否使用xDSAPIs"`
	XDS_CREDS bool `json:"xds_creds,omitempty" jsonschema:"description=是否使用xDSAPIs来接收TLS设置"`

	Algo_Name         string   `json:"algo_name" jsonschema:"required,description=校验签名使用的算法,enum=HS256,enum=HS384,enum=HS512,enum=RS256,enum=RS384,enum=RS512,enum=ES256,enum=ES384,enum=ES512,enum=EdDSA"`
	Key_Path          string   `json:"key_path" jsonschema:"required,description=保存对称加密秘钥或者非对称加密公钥pem的文件位置"`
	Default_AUD       string   `json:"default_aud" jsonschema:"description=设置默认要匹配的aud值"`
	Default_ISS_Range []string `json:"default_iss_range" jsonschema:"description=设置默认要匹配的iss值范围"`

	jwtverifier_pb.UnimplementedJwtverifierServer `json:"-"`
	opts                                          []grpc.ServerOption
	healthservice                                 *health.Server
	verifier                                      *jwthelper.Verifier
}

//Main 服务的入口函数
func (s *Server) Main() {
	// 初始化log
	log.Set(log.WithLevel(s.Log_Level),
		log.AddExtField("app_name", s.App_Name),
		log.AddExtField("app_version", s.App_Version),
	)
	log.Info("grpc服务获得参数", log.Dict{"ServiceConfig": s})

	// 创建校验器
	opts := []jwthelper.VerifierOption{}
	algo, err := utils.AlgoStrTOAlgoEnum(s.Algo_Name)
	if err != nil {
		algo = jwt_pb.EncryptionAlgorithm_HS256
		log.Warn("AlgoStrTOAlgoEnum error,use HS256 as default", log.Dict{"error": err.Error()})
	}
	if utils.IsAsymmetric(algo) {
		opts = append(opts, jwthelper.WithVerifyAlgo(algo), jwthelper.WithPemPublicKeyFromFile(s.Key_Path))
	} else {
		opts = append(opts, jwthelper.WithVerifyAlgo(algo), jwthelper.WithVerifySecretKeyFromFile(s.Key_Path))
	}
	if s.Default_AUD != "" {
		opts = append(opts, jwthelper.WithDefaultAUD(s.Default_AUD))
	}
	if s.Default_ISS_Range != nil && len(s.Default_ISS_Range) > 0 {
		opts = append(opts, jwthelper.WithDefaultISSRange(s.Default_ISS_Range...))
	}

	verifier, err := jwthelper.NewVerifier(opts...)
	if err != nil {
		log.Error("NewVerifier get error", log.Dict{"error": err.Error()})
		os.Exit(2)
	}
	s.verifier = verifier

	s.Run()
}

//PerformanceOpts 配置性能调优设置
func (s *Server) PerformanceOpts() {
	if s.opts == nil {
		s.opts = []grpc.ServerOption{}
	}

	if s.Max_Recv_Msg_Size != 0 {
		s.opts = append(s.opts, grpc.MaxRecvMsgSize(s.Max_Recv_Msg_Size))
	}
	if s.Max_Send_Msg_Size != 0 {
		s.opts = append(s.opts, grpc.MaxSendMsgSize(s.Max_Send_Msg_Size))
	}
	if s.Initial_Window_Size != 0 {
		s.opts = append(s.opts, grpc.InitialWindowSize(int32(s.Initial_Window_Size)))
	}
	if s.Initial_Conn_Window_Size != 0 {
		s.opts = append(s.opts, grpc.InitialConnWindowSize(int32(s.Initial_Conn_Window_Size)))
	}
	if s.Max_Concurrent_Streams != 0 {
		s.opts = append(s.opts, grpc.MaxConcurrentStreams(uint32(s.Max_Concurrent_Streams)))
	}
	if s.Max_Connection_Idle != 0 || s.Max_Connection_Age != 0 || s.Max_Connection_Age_Grace != 0 || s.Keepalive_Time != 0 || s.Keepalive_Timeout != 0 {
		kasp := keepalive.ServerParameters{
			MaxConnectionIdle:     time.Duration(s.Max_Connection_Idle) * time.Second,
			MaxConnectionAge:      time.Duration(s.Max_Connection_Age) * time.Second,
			MaxConnectionAgeGrace: time.Duration(s.Max_Connection_Age_Grace) * time.Second,
			Time:                  time.Duration(s.Keepalive_Time) * time.Second,
			Timeout:               time.Duration(s.Keepalive_Timeout) * time.Second,
		}
		s.opts = append(s.opts, grpc.KeepaliveParams(kasp))
	}

	if s.Keepalive_Enforcement_Min_Time != 0 || s.Keepalive_Enforcement_Permit_Without_Stream {
		kaep := keepalive.EnforcementPolicy{
			MinTime:             time.Duration(s.Keepalive_Enforcement_Min_Time) * time.Second,
			PermitWithoutStream: s.Keepalive_Enforcement_Permit_Without_Stream,
		}
		s.opts = append(s.opts, grpc.KeepaliveEnforcementPolicy(kaep))
	}
}

//TLSOpts 配置TLS设置
func (s *Server) TLSOpts() {
	if s.opts == nil {
		s.opts = []grpc.ServerOption{}
	}
	if s.Ca_Cert_Path != "" {
		cert, err := tls.LoadX509KeyPair(s.Server_Cert_Path, s.Server_Key_Path)
		if err != nil {
			log.Error("read serv pem file error:", log.Dict{"err": err.Error(), "Cert_path": s.Server_Cert_Path, "Key_Path": s.Server_Key_Path})
			os.Exit(2)
		}
		capool := x509.NewCertPool()
		caCrt, err := ioutil.ReadFile(s.Ca_Cert_Path)
		if err != nil {
			log.Error("read ca pem file error:", log.Dict{"err": err.Error(), "path": s.Ca_Cert_Path})
			os.Exit(2)
		}
		capool.AppendCertsFromPEM(caCrt)
		tlsconf := &tls.Config{
			RootCAs:      capool,
			ClientAuth:   tls.RequireAndVerifyClientCert, // 检验客户端证书
			Certificates: []tls.Certificate{cert},
		}
		if s.Client_Crl_Path != "" {
			clipool := x509.NewCertPool()
			cliCrt, err := ioutil.ReadFile(s.Client_Crl_Path)
			if err != nil {
				log.Error("read pem file error:", log.Dict{"err": err.Error(), "path": s.Client_Crl_Path})
				os.Exit(2)
			}
			clipool.AppendCertsFromPEM(cliCrt)
			tlsconf.ClientCAs = clipool
		}
		creds := credentials.NewTLS(tlsconf)
		s.opts = append(s.opts, grpc.Creds(creds))
	} else {
		creds, err := credentials.NewServerTLSFromFile(s.Server_Cert_Path, s.Server_Key_Path)
		if err != nil {
			log.Error("Failed to Listen as a TLS Server", log.Dict{"error": err.Error()})
			os.Exit(2)
		}
		s.opts = append(s.opts, grpc.Creds(creds))
	}
	log.Info("server will start use TLS")
}

//RunServer 启动服务
func (s *Server) RunServer() {
	lis, err := net.Listen("tcp", s.Address)
	if err != nil {
		log.Error("Failed to Listen", log.Dict{"error": err.Error(), "address": s.Address})
		os.Exit(1)
	}
	s.PerformanceOpts()
	if s.XDS {
		// 注意目前的XDS模式不支持反射,且健康监测不能和服务主体在同一个接口(现在默认为服务端口号+1)
		creds := insecure.NewCredentials()
		var err error
		if s.XDS_CREDS {
			creds, err = xdscreds.NewServerCredentials(xdscreds.ServerOptions{FallbackCreds: insecure.NewCredentials()})
		}
		if err != nil {
			log.Error("failed to create server-side xDS credentials", log.Dict{"error": err.Error()})
			os.Exit(2)
		}
		s.opts = append(s.opts, grpc.Creds(creds))
		log.Info("server will start use XDS_CREDS")
		gs := xds.NewGRPCServer(s.opts...)
		defer gs.Stop()
		jwtverifier_pb.RegisterJwtverifierServer(gs, s)
		// 注册健康检查
		hostinfo := strings.Split(s.Address, ":")
		if len(hostinfo) != 2 {
			log.Error("address format not ok", log.Dict{"address": s.Address})
			os.Exit(2)
		}
		port, err := strconv.Atoi(hostinfo[1])
		if err != nil {
			log.Error("address port not int", log.Dict{"address": s.Address})
			os.Exit(2)
		}
		healthaddress := fmt.Sprintf("%s:%d", hostinfo[0], port+1)
		healthLis, err := net.Listen("tcp4", healthaddress)
		if err != nil {
			log.Error("Health Service Failed to Listen", log.Dict{"error": err.Error(), "address": healthaddress})
			os.Exit(1)
		}
		healthServer := grpc.NewServer()
		s.healthservice = health.NewServer()
		s.healthservice.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
		healthpb.RegisterHealthServer(healthServer, s.healthservice)
		// 无法注册反射

		// 启动服务
		log.Info("Server Start", log.Dict{"address": s.Address, "health_service_addres": healthaddress})
		go func() {
			err := gs.Serve(lis)
			if err != nil {
				log.Error("Failed to Serve", log.Dict{"error": err})
				os.Exit(1)
			}
		}()
		go healthServer.Serve(healthLis)
		// 等待中断信号以优雅地关闭服务器（设置 3 秒的超时时间）
		quit := make(chan os.Signal, 3)
		signal.Notify(quit, os.Interrupt)
		<-quit
		log.Info("Shutdown Server ...")
		gs.GracefulStop()
		healthServer.GracefulStop()
	} else {
		if s.Server_Cert_Path != "" && s.Server_Key_Path != "" {
			s.TLSOpts()
		}
		gs := grpc.NewServer(s.opts...)
		defer gs.Stop()
		// 注册健康检查
		s.healthservice = health.NewServer()
		s.healthservice.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
		healthpb.RegisterHealthServer(gs, s.healthservice)

		// 注册反射
		reflection.Register(gs)
		// 注册服务
		jwtverifier_pb.RegisterJwtverifierServer(gs, s)

		// 启动服务
		log.Info("Server Start", log.Dict{"address": s.Address})
		err = gs.Serve(lis)
		if err != nil {
			log.Error("Failed to Serve", log.Dict{"error": err})
			os.Exit(1)
		}
	}
}

//Run 执行grpc服务
func (s *Server) Run() {
	s.RunServer()
}
