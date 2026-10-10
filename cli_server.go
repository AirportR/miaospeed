package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"

	"github.com/airportr/miaospeed/preconfigs"
	"github.com/airportr/miaospeed/service"
	"github.com/airportr/miaospeed/utils"
)

// connectList collects every -connect value.
type connectList []string

func (c *connectList) String() string { return strings.Join(*c, ",") }

func (c *connectList) Set(value string) error {
	*c = append(*c, utils.SplitConnectValues(value)...)
	return nil
}

func InitConfigServer() *utils.GlobalConfig {
	gcfg := &utils.GCFG
	sflag := flag.NewFlagSet(cmdName+" server", flag.ExitOnError)
	sflag.StringVar(&gcfg.Token, "token", "", "specify the token used to sign request")
	sflag.StringVar(&gcfg.Binder, "bind", "", "bind a socket, can be format like 0.0.0.0:8080 or /tmp/unix_socket")
	sflag.StringVar(&gcfg.PprofBinder, "pprof", "", "enable pprof server, bind address format like 127.0.0.1:6060")
	sflag.UintVar(&gcfg.ConnTaskTreading, "connthread", 64, "parallel threads when processing normal connectivity tasks")
	sflag.UintVar(&gcfg.TaskLimit, "tasklimit", 1000, "limit of tasks in queue, default with 1000")
	sflag.Uint64Var(&gcfg.SpeedLimit, "speedlimit", 0, "speed ratelimit (in Bytes per Second), default with no limits")
	sflag.UintVar(&gcfg.PauseSecond, "pausesecond", 0, "pause such period after each speed job (seconds)")
	sflag.BoolVar(&gcfg.MiaoKoSignedTLS, "mtls", false, "enable embedded certs for TLS verification.")
	sflag.BoolVar(&gcfg.NoSpeedFlag, "nospeed", false, "decline all download speedtest requests")
	sflag.BoolVar(&gcfg.EnableUploadSpeedFlag, "upload", false, "enable all upload speedtest requests")
	sflag.BoolVar(&gcfg.EnableIPv6, "ipv6", false, "enable ipv6 support")
	sflag.StringVar(&gcfg.MaxmindDB, "mmdb", "", "reroute all geoip query to local mmdbs. for example: test.mmdb,testcity.mmdb")
	path := sflag.String("path", "", "specific websocket path you want, default '/'")
	allowIP := sflag.String("allowip", "0.0.0.0/0,::/0", "allow ip range, can be format like 192.168.1.0/24,10.12.13.2")
	whiteList := sflag.String("whitelist", "", "bot id whitelist, can be format like 1111,2222,3333")
	pubKeyStr := sflag.String("serverpublickey", "", "server certificate (PEM format), replaces the embedded ones")
	privKeyStr := sflag.String("serverprivatekey", "", "private key (PEM format) for -serverpublickey")
	clientCAStr := sflag.String("clientca", "", "path to client CA certificate (PEM) - enables optional mTLS: verify client cert if presented, allow without")
	demoMode := sflag.Bool("demo", false, "run server in demo mode with default configs")
	var connectURLs connectList
	sflag.Var(&connectURLs, "connect", "reverse connection: dial OUT to a websocket endpoint hosted by the client, e.g. wss://panel.example.com/reverse. Repeat the flag (or separate the urls with a comma) to serve several endpoints. Useful when this host has no public ip")

	parseFlag(sflag)

	validEndpoints, rejectedEndpoints, duplicatedEndpoints := utils.ParseConnectEndpoints(connectURLs)
	for _, problem := range rejectedEndpoints {
		utils.DErrorf("MiaoSpeed Server | Invalid -connect endpoint, %s", problem)
	}
	if len(rejectedEndpoints) > 0 {
		os.Exit(1)
	}
	for _, duplicated := range duplicatedEndpoints {
		utils.DWarnf("MiaoSpeed Server | Duplicated -connect endpoint dropped, url=%s", duplicated)
	}

	gcfg.ConnectURLs = validEndpoints
	if len(validEndpoints) > 0 {
		gcfg.ConnectURL = validEndpoints[0]
		if gcfg.Token == "" {
			utils.DErrorf("MiaoSpeed Server | -connect requires -token to authenticate with the client")
			os.Exit(1)
		}
		if gcfg.Binder == "" {
			utils.DWarnf("MiaoSpeed Server | -connect is set without -bind, running in reverse-only mode (no inbound listener)")
		}
		if len(validEndpoints) > 1 {
			utils.DWarnf("MiaoSpeed Server | Serving %d reverse endpoints", len(validEndpoints))
		}
	}

	gcfg.WhiteList = make([]string, 0)
	if *whiteList != "" {
		gcfg.WhiteList = strings.Split(*whiteList, ",")
	}
	if *allowIP != "" {
		if *allowIP == "0.0.0.0/0,::/0" {
			utils.DWarnf("MiaoSpeed Server | Allow ip range is set to 0.0.0.0/0,::/0, which means any ip can access this server.")
		}
		gcfg.AllowIPs = strings.Split(*allowIP, ",")
	}
	if *path != "" {
		if *path == "/" {
			gcfg.Path = "/"
		}
		gcfg.Path = "/" + strings.TrimPrefix(*path, "/")
	} else {
		// deprecated
		gcfg.Path = "/"
	}

	// 处理 demo 模式
	if *demoMode {
		if gcfg.Binder == "" {
			gcfg.Binder = "127.0.0.1:8765"
		}
		if gcfg.Token == "" {
			gcfg.Token = utils.RandomUUID()
		}
		gcfg.MiaoKoSignedTLS = true
		gcfg.EnableIPv6 = true
		if *path == "" {
			randomPath := "/" + utils.RandomUUID()
			gcfg.Path = randomPath
		}

		// 将配置信息编码为 base64 JSON 字符串并输出
		configBytes, _ := json.Marshal(gcfg)
		configBase64 := base64.StdEncoding.EncodeToString(configBytes)
		configBase64 = "miaospeed://" + configBase64
		fmt.Println("===============================\tCopy it to your client\t================================")
		fmt.Println(configBase64)
		fmt.Println("===============================\tEnd of line\t================================")
	}

	// Nothing to serve: without -bind the server does not listen and without
	// -connect it does not dial out. Fail loudly instead of idling forever.
	if len(gcfg.ConnectEndpoints()) == 0 && gcfg.Binder == "" {
		utils.DErrorf("MiaoSpeed Server | both -bind and -connect are empty, nothing to serve")
		os.Exit(1)
	}

	if gcfg.Path == "/" {
		utils.DWarnf("MiaoSpeed Server | Using an unsafe websocket path: %s", gcfg.Path)
	} else {
		utils.DWarnf("MiaoSpeed Server | Using a custom websocket path: %s", gcfg.Path)
	}
	if *pubKeyStr != "" || *privKeyStr != "" {
		// The pair replaces the embedded certificates
		if *pubKeyStr == "" || *privKeyStr == "" {
			utils.DErrorf("MiaoSpeed Server | -serverpublickey and -serverprivatekey must be given together")
			os.Exit(1)
		}
		pubKey := utils.ReadFile(*pubKeyStr)
		priKey := utils.ReadFile(*privKeyStr)
		if pubKey == "" || priKey == "" {
			utils.DErrorf("MiaoSpeed Server | cannot read the certificate pair %s / %s", *pubKeyStr, *privKeyStr)
			os.Exit(1)
		}
		if err := preconfigs.SetServerCertificate(pubKey, priKey); err != nil {
			utils.DErrorf("MiaoSpeed Server | cannot load the TLS certificate %s, error=%s", *pubKeyStr, err.Error())
			os.Exit(1)
		}
		utils.DWarnf("MiaoSpeed Server | overriding the embedded TLS certificates | %s", *pubKeyStr)
	}
	if *clientCAStr != "" {
		if !gcfg.MiaoKoSignedTLS {
			utils.DWarnf("MiaoSpeed Server | clientca is configured but -mtls is disabled; client certificate verification will not be used")
		}
		caData := utils.ReadFile(*clientCAStr)
		if caData == "" {
			utils.DErrorf("Failed to read client CA certificate from %s", *clientCAStr)
			os.Exit(1)
		}
		if !preconfigs.LoadClientCAFromPEM(caData) {
			utils.DErrorf("Failed to parse client CA certificate from %s, no valid PEM data", *clientCAStr)
			os.Exit(1)
		}
		utils.DLog("Loaded client CA for optional mTLS verification")
	}
	return gcfg
}

func RunCliServer() {
	fmt.Println(utils.LOGO)
	InitConfigServer()
	utils.DWarnf("MiaoSpeed version: %s, vendor(mihomo) version: %s", utils.VERSION, utils.MihomoVersion)

	// load maxmind db
	if utils.LoadMaxMindDB(utils.GCFG.MaxmindDB) != nil {
		os.Exit(1)
	}

	// start task server
	go service.StartTaskServer()
	startPprofServer()

	// reverse connection: dial out to the client. Can run alone or
	// alongside the inbound listener (both share the task polls).
	if len(utils.GCFG.ConnectEndpoints()) > 0 {
		go service.RunReverseConnector()
	}

	// start api server
	if utils.GCFG.Binder != "" {
		service.CleanUpServer()
		go service.InitServer()
	}

	<-utils.MakeSysChan()

	// clean up
	service.CleanUpServer()
	utils.DLog("Shutting down.")
}

func startPprofServer() {
	pprofBind := strings.TrimSpace(utils.GCFG.PprofBinder)
	if pprofBind == "" {
		return
	}

	go func() {
		utils.DWarnf("MiaoSpeed PProf | Start Listening, bind=%s", pprofBind)
		if err := http.ListenAndServe(pprofBind, nil); err != nil {
			utils.DErrorf("MiaoSpeed PProf | Cannot serve on socket %s, error=%s", pprofBind, err.Error())
		}
	}()
}
