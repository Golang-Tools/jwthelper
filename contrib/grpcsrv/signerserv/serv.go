// 签名服务端:提供jwt签名能力的grpc服务
package signerserv

import (
	"os"
	"time"

	"github.com/Golang-Tools/idgener"
	"github.com/Golang-Tools/jwthelper/contrib/grpcsrv/serverbase"
	"github.com/Golang-Tools/jwthelper/contrib/pb/signerpb"
	jwthelper "github.com/Golang-Tools/jwthelper/v4"
	log "github.com/Golang-Tools/loggerhelper/v4"
	"github.com/Golang-Tools/optparams"
	grpc "google.golang.org/grpc"
)

// Server 签名器的grpc服务端。
// 注意:公共配置字段必须平铺在该结构体上(schema-entry-go的配置解析不支持内嵌结构),
// 公共配置字段变更时需要同步serverbase.Options与Options方法。
type Server struct {
	App_Name    string `json:"app_name,omitempty" jsonschema:"required,description=服务名,default=jwthelper_signerrpc"`
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

	/**
	在这里补充其他配置项(注意去掉注释)
	*/
	Algo_Name                         string `json:"algo_name" jsonschema:"required,description=签名使用的算法,enum=HS256,enum=HS384,enum=HS512,enum=RS256,enum=RS384,enum=RS512,enum=ES256,enum=ES384,enum=ES512,enum=EdDSA"`
	Key_Path                          string `json:"key_path" jsonschema:"required,description=保存对称加密秘钥或者非对称加密私钥pem的文件位置"`
	Iss                               string `json:"iss,omitempty" jsonschema:"description=签发人默认为机器id-算法名"`
	Default_TTL_Minute                int    `json:"default_ttl_minute,omitempty" jsonschema:"description=默认token超时单位min"`
	Default_Effective_Interval_Minute int    `json:"default_effective_interval_minute,omitempty" jsonschema:"description=默认token生效离签发时间间隔单位min"`
	JtiGen_Name                       string `json:"jtigen_name,omitempty" jsonschema:"description=jti的生成器默认uuidv4,enum=uuidv4,enum=snowflake,enum=sonyflake,default=uuidv4"`

	signerpb.UnimplementedJwtsignerServer `json:"-"`
	signer                                *jwthelper.Signer
}

// NewServer 创建服务端配置对象
func NewServer() *Server {
	return &Server{}
}

// Options 返回公共配置的值快照(供serverbase中的公共骨架使用)
func (s *Server) Options() *serverbase.Options {
	return &serverbase.Options{
		App_Name:    s.App_Name,
		App_Version: s.App_Version,
		Address:     s.Address,
		Log_Level:   s.Log_Level,

		Max_Recv_Msg_Size:                           s.Max_Recv_Msg_Size,
		Max_Send_Msg_Size:                           s.Max_Send_Msg_Size,
		Initial_Window_Size:                         s.Initial_Window_Size,
		Initial_Conn_Window_Size:                    s.Initial_Conn_Window_Size,
		Max_Concurrent_Streams:                      s.Max_Concurrent_Streams,
		Max_Connection_Idle:                         s.Max_Connection_Idle,
		Max_Connection_Age:                          s.Max_Connection_Age,
		Max_Connection_Age_Grace:                    s.Max_Connection_Age_Grace,
		Keepalive_Time:                              s.Keepalive_Time,
		Keepalive_Timeout:                           s.Keepalive_Timeout,
		Keepalive_Enforcement_Min_Time:              s.Keepalive_Enforcement_Min_Time,
		Keepalive_Enforcement_Permit_Without_Stream: s.Keepalive_Enforcement_Permit_Without_Stream,

		Server_Cert_Path: s.Server_Cert_Path,
		Server_Key_Path:  s.Server_Key_Path,
		Ca_Cert_Path:     s.Ca_Cert_Path,
		Client_Crl_Path:  s.Client_Crl_Path,

		XDS:       s.XDS,
		XDS_CREDS: s.XDS_CREDS,
	}
}

// Main 服务的入口函数
func (s *Server) Main() {
	// 初始化log
	serverbase.InitLogger(s.Options(), s)

	// 创建签名器
	opts := []optparams.Option[jwthelper.SignerOptions]{}
	algo, err := jwthelper.ParseAlgo(s.Algo_Name)
	if err != nil {
		algo = jwthelper.AlgoHS256
		log.Warn("ParseAlgo error,use HS256 as default", log.Dict{"error": err.Error()})
	}
	if jwthelper.IsAsymmetric(algo) {
		opts = append(opts, jwthelper.WithSignAlgo(algo), jwthelper.WithPemPrivateKeyFromFile(s.Key_Path))
	} else {
		opts = append(opts, jwthelper.WithSignAlgo(algo), jwthelper.WithSignSecretKeyFromFile(s.Key_Path))
	}

	if s.Iss != "" {
		opts = append(opts, jwthelper.WithSignIss(s.Iss))
	}
	if s.Default_TTL_Minute > 0 {
		opts = append(opts, jwthelper.WithDefaultTTL(time.Duration(s.Default_TTL_Minute)*time.Minute))
	}
	if s.Default_Effective_Interval_Minute > 0 {
		opts = append(opts, jwthelper.WithDefaultEffectiveInterval(time.Duration(s.Default_Effective_Interval_Minute)*time.Minute))
	}

	if s.JtiGen_Name != "" {
		switch s.JtiGen_Name {
		case "uuidv4":
			{
				idgen, err := idgener.IDGenNameToIDGen(idgener.IDGEN_UUIDV4)
				if err != nil {
					log.Warn("IDGenNameToIDGen get error, use default")
				} else {
					opts = append(opts, jwthelper.WithSignJtiGen(idgen))
				}
			}
		case "snowflake":
			{
				idgen, err := idgener.IDGenNameToIDGen(idgener.IDGEN_SNOWFLAKE)
				if err != nil {
					log.Warn("IDGenNameToIDGen get error, use default")
				} else {
					opts = append(opts, jwthelper.WithSignJtiGen(idgen))
				}
			}
		case "sonyflake":
			{
				idgen, err := idgener.IDGenNameToIDGen(idgener.IDGEN_SNOYFLAKE)
				if err != nil {
					log.Warn("IDGenNameToIDGen get error, use default")
				} else {
					opts = append(opts, jwthelper.WithSignJtiGen(idgen))
				}
			}
		default:
			{
				log.Error("IDGenNameToIDGen get unsupported JtiGen_Name, use default", log.Dict{"JtiGen_Name": s.JtiGen_Name})
				os.Exit(2)
			}
		}
	}
	signer, err := jwthelper.NewSigner(opts...)
	if err != nil {
		log.Error("NewSigner get error", log.Dict{"error": err.Error()})
		os.Exit(2)
	}
	s.signer = signer
	serverbase.RunServer(s.Options(), func(gs grpc.ServiceRegistrar) {
		signerpb.RegisterJwtsignerServer(gs, s)
	})
}
