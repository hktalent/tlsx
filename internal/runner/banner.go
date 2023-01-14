package runner

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	fileutil "github.com/projectdiscovery/utils/file"
	"strings"
)

var banner = fmt.Sprintf(`  

  _____ _    _____  __
 |_   _| |  / __\ \/ /
   | | | |__\__ \>  < 
   |_| |____|___/_/\_\	%s
`, version)

var version = "v1.0.3"

// validateOptions validates the provided options for crawler
func (r *Runner) validateOptions() error {
	r.hasStdin = fileutil.HasStdin()

	if r.options.Retries == 0 {
		r.options.Retries = 1
	}
	probeSpecified := r.options.SO || r.options.TLSVersion || r.options.Cipher || r.options.Expired || r.options.SelfSigned || r.options.Hash != "" || r.options.Jarm || r.options.MisMatched || r.options.Revoked || r.options.WildcardCertCheck
	if r.options.RespOnly && probeSpecified {
		return errors.New("resp-only flag can only be used with san and cn flags")
	}
	if (r.options.SAN || r.options.CN) && probeSpecified {
		return errors.New("san or cn flag cannot be used with other probes")
	}
	if !r.hasStdin && len(r.options.Inputs) == 0 && r.options.InputList == "" {
		return errors.New("no input provided for enumeration")
	}
	if len(r.options.Ports) == 0 {
		// Append port 443 for default ports
		// top https port
		// https://www.shodan.io/search/facet?query=https&facet=port
		var aShodanHttpsTop = strings.Split("80,443,8008,2082,2087,2086,2096,5001,5000,2077,2095,8080,10443,2079,2083,8443,21,8081,4443,2222,8090,7080,9090,3128,9443,8888,10000,444,8000,4100,20000,4433,81,8800,9000,25,3000,8083,1500,1337,5672,11000,7001,8089,10243,2030,2031,9001,8181,10001,12000,11210,11211,7443,3001,10250,22222,88,4040,50000,8880,9091,9999,9002,465,587,18081,8788,11371,11300,49153,49152,8887,3702,8001,6443,19000,6080,7777,8088,8889,53,9080,82,5353,9306,8500,8082,8834,2121,9200,5555,3306,4848,7000,27140,9527,14147,83,60001,1000,17000,7071,23424,13579,21025,25105,85,32400,5222,16992,19071,28017,32764,50050,23023,27017,37215,50100,52869,41800,50070,9123,51106,33060,55554,44158,8009,61616,55442,16010,5006,37777,35000,25001,20547,1080,9998,9943,8086,7081,2020,6308,8899,5005,993,8140,8139,8010,31337,14265,9191,2223,5002,5050,1024,7548,9988,8085,5984,9098,84,8099,5172,9997,4430,8765,631,55443,9966,5080,8040,8990,9007,90,8002,8859,8857,3002,8200,1025,4643,8084,8060,8020,3790,8018,89,5010,3333,8123,8383,9010,8866,9082,9009,2443,1234,888,666,23,880,1023,3780,22,5443,5986,2323,5500,7547,6002,16993,8444,7474,8098,5800,5601,6666,9295,2080,5569,2376,5003,8180,445,8999,9092,55553,8989,8852,7010,8095,8091,9800,1926,8069,8011,9595,311,3443,8087,8334,9981,8112,8282,1900,9008,4321,8111,9088,102,5858,8100,25565,6667,9761,9944,5801,9869,4949,9006,9160,5900,1935,2053,2002,2480,9003,4567,8005,9005,86,143,9084,7779,2008,8333,8006,8096,3551,6664,8055,99,5560,4001,5985,221,8021,8003,800,873,2067,4282,7989,448,995,8649,5432,990,180,5901,9004,1400,2154,7657,9050,7634,5357,3080,4782,3541,8050,1883,3542,4664,3301,4840,2332,8850,3689,5004,7218,4000,91,161,1311,3749,7070,8988,1026,4506,1471,4063,1741,9042,9201,8447,8575,1604,8004,1925,1111,1050,8585,8445,8012,5600,9202,8446,110,8015,2375,4646,7002,8545,2021,6633,1028,2221,3052,503,9300,2100,6653,9990,9203,8092,9204,1110,4022,8442,2048,8043,9205,1027,9209,593,6789,9876,6001,6565,8101,9389,502,9212,9301,902,450,9222,9210,9211,9217,1029,9221", ",")
		r.options.Ports = append(r.options.Ports, aShodanHttpsTop[0:10]...)
	}
	if r.options.CertsOnly && !(r.options.ScanMode == "ztls" || r.options.ScanMode == "auto") {
		return errors.New("scan-mode must be ztls or auto with certs-only option")
	}
	if r.options.CertsOnly || r.options.Ja3 {
		r.options.ScanMode = "ztls" // force setting ztls when using certs-only
	}
	if r.options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}

	if r.options.Jarm && r.options.Delay != "" {
		gologger.Info().Label("WRN").Msg("Using connection pooling for jarm hash calculation, delay will not work as expected")
	}
	return nil
}

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
}
