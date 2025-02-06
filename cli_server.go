package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/airportr/miaospeed/preconfigs"
	"github.com/airportr/miaospeed/service"
	"github.com/airportr/miaospeed/utils"
)

func InitConfigServer() *utils.GlobalConfig {
	gcfg := &utils.GCFG
	sflag := flag.NewFlagSet(cmdName+" server", flag.ExitOnError)
	sflag.StringVar(&gcfg.Token, "token", "", "specify the token used to sign request")
	sflag.StringVar(&gcfg.Binder, "bind", "", "bind a socket, can be format like 0.0.0.0:8080 or /tmp/unix_socket")
	sflag.UintVar(&gcfg.ConnTaskTreading, "connthread", 64, "parallel threads when processing normal connectivity tasks")
	sflag.UintVar(&gcfg.TaskLimit, "tasklimit", 1000, "limit of tasks in queue, default with 1000")
	sflag.Uint64Var(&gcfg.SpeedLimit, "speedlimit", 0, "speed ratelimit (in Bytes per Second), default with no limits")
	sflag.UintVar(&gcfg.PauseSecond, "pausesecond", 0, "pause such period after each speed job (seconds)")
	sflag.BoolVar(&gcfg.MiaoKoSignedTLS, "mtls", false, "enable miaoko certs for tls verification")
	sflag.BoolVar(&gcfg.NoSpeedFlag, "nospeed", false, "decline all speedtest requests")
	sflag.BoolVar(&gcfg.EnableIPv6, "ipv6", false, "enable ipv6 support")
	sflag.StringVar(&gcfg.MaxmindDB, "mmdb", "", "reroute all geoip query to local mmdbs. for example: test.mmdb,testcity.mmdb")
	path := sflag.String("path", "", "specific websocket path you want, default '/'")
	allowIP := sflag.String("allowip", "0.0.0.0/0,::/0", "allow ip range, can be format like 192.168.1.0/24,10.12.13.2")
	whiteList := sflag.String("whitelist", "", "bot id whitelist, can be format like 1111,2222,3333")
	pubKeyStr := sflag.String("serverpublickey", "", "specific the sever public key (PEM format)")
	privKeyStr := sflag.String("serverprivatekey", "", "specific the sever private key (PEM format)")
	parseFlag(sflag)

	gcfg.WhiteList = make([]string, 0)
	if *whiteList != "" {
		gcfg.WhiteList = strings.Split(*whiteList, ",")
	}
	if *allowIP != "" {
		if *allowIP == "0.0.0.0/0,::/0" {
			utils.DWarnf("MiaoSpeed Server | allow ip range is set to 0.0.0.0/0,::/0, which means any ip (full stack) can access this server, please use it with caution")
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
	if gcfg.Path == "/" {
		utils.DWarnf("MiaoSpeed Server | using an unsafe websocket connection path: %s", gcfg.Path)
	} else {
		utils.DWarnf("MiaoSpeed Server | using a custom websocket connection path: %s", gcfg.Path)
	}
	if pubKey := utils.ReadFile(*pubKeyStr); pubKey != "" {
		utils.DLog("Override predefined tls certificates")
		preconfigs.MIAOKO_TLS_CRT = pubKey
	}
	if priKey := utils.ReadFile(*privKeyStr); priKey != "" {
		utils.DLog("Override predefined tls key")
		preconfigs.MIAOKO_TLS_KEY = priKey
	}
	return gcfg
}

func RunCliServer() {
	fmt.Println(utils.LOGO)
	InitConfigServer()
	utils.DWarnf("MiaoSpeed speedtesting client %s", utils.VERSION)

	// load maxmind db
	if utils.LoadMaxMindDB(utils.GCFG.MaxmindDB) != nil {
		os.Exit(1)
	}

	// start task server
	go service.StartTaskServer()

	// start api server
	service.CleanUpServer()
	go service.InitServer()

	<-utils.MakeSysChan()

	// clean up
	service.CleanUpServer()
	utils.DLog("shutting down.")
}
