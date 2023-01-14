package main

import (
	"os"
	"strings"

	util "github.com/hktalent/go-utils"
	"github.com/hktalent/tlsx/internal/runner"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/openssl"
	errorutils "github.com/projectdiscovery/utils/errors"
)

var (
	cfgFile string
	options = &clients.Options{}
)

func main() {
	util.DoInitAll()
	if err := process(); err != nil {
		gologger.Fatal().Msgf("Could not process: %s", err)
	}
	util.Wg.Wait()
	util.CloseAll()
}

func process() error {
	if err := readFlags(); err != nil {
		return errors.Wrap(err, "could not read flags")
	}
	runner, err := runner.New(options)
	if err != nil {
		return errors.Wrap(err, "could not create runner")
	}
	if runner == nil {
		return nil
	}
	if err := runner.Execute(); err != nil {
		return errors.Wrap(err, "could not execute runner")
	}
	if err := runner.Close(); err != nil {
		return errors.Wrap(err, "could not close runner")
	}
	return nil
}

func readFlags() error {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`TLSX is a tls data gathering and analysis toolkit.`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&options.Inputs, "host", "u", nil, "target host to scan (-u INPUT1,INPUT2)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&options.InputList, "list", "l", "", "target list to scan (-l INPUT_FILE)"),
		flagSet.StringSliceVarP(&options.Ports, "port", "p", strings.Split("80,443,8008,2082,2087,2086,2096,5001,5000,2077,2095,8080,10443,2079,2083,8443,21,8081,4443,2222,8090,7080,9090,3128,9443,8888,10000,444,8000,4100,20000,4433,81,8800,9000,25,3000,8083,1500,1337,5672,11000,7001,8089,10243,2030,2031,9001,8181,10001,12000,11210,11211,7443,3001,10250,22222,88,4040,50000,8880,9091,9999,9002,465,587,18081,8788,11371,11300,49153,49152,8887,3702,8001,6443,19000,6080,7777,8088,8889,53,9080,82,5353,9306,8500,8082,8834,2121,9200,5555,3306,4848,7000,27140,9527,14147,83,60001,1000,17000,7071,23424,13579,21025,25105,85,32400,5222,16992,19071,28017,32764,50050,23023,27017,37215,50100,52869,41800,50070,9123,51106,33060,55554,44158,8009,61616,55442,16010,5006,37777,35000,25001,20547,1080,9998,9943,8086,7081,2020,6308,8899,5005,993,8140,8139,8010,31337,14265,9191,2223,5002,5050,1024,7548,9988,8085,5984,9098,84,8099,5172,9997,4430,8765,631,55443,9966,5080,8040,8990,9007,90,8002,8859,8857,3002,8200,1025,4643,8084,8060,8020,3790,8018,89,5010,3333,8123,8383,9010,8866,9082,9009,2443,1234,888,666,23,880,1023,3780,22,5443,5986,2323,5500,7547,6002,16993,8444,7474,8098,5800,5601,6666,9295,2080,5569,2376,5003,8180,445,8999,9092,55553,8989,8852,7010,8095,8091,9800,1926,8069,8011,9595,311,3443,8087,8334,9981,8112,8282,1900,9008,4321,8111,9088,102,5858,8100,25565,6667,9761,9944,5801,9869,4949,9006,9160,5900,1935,2053,2002,2480,9003,4567,8005,9005,86,143,9084,7779,2008,8333,8006,8096,3551,6664,8055,99,5560,4001,5985,221,8021,8003,800,873,2067,4282,7989,448,995,8649,5432,990,180,5901,9004,1400,2154,7657,9050,7634,5357,3080,4782,3541,8050,1883,3542,4664,3301,4840,2332,8850,3689,5004,7218,4000,91,161,1311,3749,7070,8988,1026,4506,1471,4063,1741,9042,9201,8447,8575,1604,8004,1925,1111,1050,8585,8445,8012,5600,9202,8446,110,8015,2375,4646,7002,8545,2021,6633,1028,2221,3052,503,9300,2100,6653,9990,9203,8092,9204,1110,4022,8442,2048,8043,9205,1027,9209,593,6789,9876,6001,6565,8101,9389,502,9212,9301,902,450,9222,9210,9211,9217,1029,9221", ","), "target port to connect (default 443)", goflags.FileCommaSeparatedStringSliceOptions),
	)

	availableScanModes := []string{"ctls", "ztls"}
	if openssl.IsAvailable() {
		availableScanModes = append(availableScanModes, "openssl")
	}
	availableScanModes = append(availableScanModes, "auto")

	flagSet.CreateGroup("scan-mode", "Scan-Mode",
		flagSet.StringVarP(&options.ScanMode, "scan-mode", "sm", "auto", "tls connection mode to use ("+strings.Join(availableScanModes, ", ")+")"),
		flagSet.BoolVarP(&options.CertsOnly, "pre-handshake", "ps", false, "enable pre-handshake tls connection (early termination) using ztls"),
		flagSet.BoolVarP(&options.ScanAllIPs, "scan-all-ips", "sa", false, "scan all ips for a host (default false)"),
		flagSet.StringSliceVarP(&options.IPVersion, "ip-version", "iv", nil, "ip version to use (4, 6) (default 4)", goflags.NormalizedStringSliceOptions),
	)

	flagSet.CreateGroup("probes", "Probes",
		flagSet.BoolVar(&options.SAN, "san", false, "display subject alternative names"),
		flagSet.BoolVar(&options.CN, "cn", false, "display subject common names"),
		flagSet.BoolVar(&options.SO, "so", false, "display subject organization name"),
		flagSet.BoolVarP(&options.TLSVersion, "tls-version", "tv", false, "display used tls version"),
		flagSet.BoolVar(&options.Cipher, "cipher", false, "display used cipher"),
		flagSet.StringVar(&options.Hash, "hash", "", "display certificate fingerprint hashes (md5,sha1,sha256)"),
		flagSet.BoolVar(&options.Jarm, "jarm", false, "display jarm fingerprint hash"),
		flagSet.BoolVar(&options.Ja3, "ja3", false, "display ja3 fingerprint hash (using ztls)"),
		flagSet.BoolVarP(&options.WildcardCertCheck, "wildcard-cert", "wc", false, "display host with wildcard ssl certificate"),
		flagSet.BoolVarP(&options.ProbeStatus, "probe-status", "tps", false, "display tls probe status"),
		flagSet.BoolVarP(&options.TlsVersionsEnum, "version-enum", "ve", false, "enumerate and display supported tls versions"),
		flagSet.BoolVarP(&options.TlsCiphersEnum, "cipher-enum", "ce", false, "enumerate and display supported cipher"),
		flagSet.BoolVarP(&options.ClientHello, "client-hello", "ch", false, "include client hello in json output (ztls mode only)"),
		flagSet.BoolVarP(&options.ServerHello, "server-hello", "sh", false, "include server hello in json output (ztls mode only)"),
	)

	flagSet.CreateGroup("misconfigurations", "Misconfigurations",
		flagSet.BoolVarP(&options.Expired, "expired", "ex", false, "display host with host expired certificate"),
		flagSet.BoolVarP(&options.SelfSigned, "self-signed", "ss", false, "display host with self-signed certificate"),
		flagSet.BoolVarP(&options.MisMatched, "mismatched", "mm", false, "display host with mismatched certificate"),
		flagSet.BoolVarP(&options.Revoked, "revoked", "re", false, "display host with revoked certificate"),
	)

	flagSet.CreateGroup("configs", "Configurations",
		flagSet.StringVar(&cfgFile, "config", "", "path to the tlsx configuration file"),
		flagSet.StringSliceVarP(&options.Resolvers, "resolvers", "r", nil, "list of resolvers to use", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&options.CACertificate, "cacert", "cc", "", "client certificate authority file"),
		flagSet.StringSliceVarP(&options.Ciphers, "cipher-input", "ci", nil, "ciphers to use with tls connection", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringSliceVar(&options.ServerName, "sni", nil, "tls sni hostname to use", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.BoolVarP(&options.RandomForEmptyServerName, "random-sni", "rs", false, "use random sni when empty"),
		flagSet.StringVar(&options.MinVersion, "min-version", "", "minimum tls version to accept (ssl30,tls10,tls11,tls12,tls13)"),
		flagSet.StringVar(&options.MaxVersion, "max-version", "", "maximum tls version to accept (ssl30,tls10,tls11,tls12,tls13)"),
		flagSet.BoolVarP(&options.AllCiphers, "all-ciphers", "ac", true, "send all ciphers as accepted inputs"),
		flagSet.BoolVarP(&options.Cert, "certificate", "cert", false, "include certificates in json output (PEM format)"),
		flagSet.BoolVarP(&options.TLSChain, "tls-chain", "tc", false, "include certificates chain in json output"),
		flagSet.BoolVarP(&options.VerifyServerCertificate, "verify-cert", "vc", false, "enable verification of server certificate"),
		flagSet.StringVarP(&options.OpenSSLBinary, "openssl-binary", "ob", "", "OpenSSL Binary Path"),
	)

	flagSet.CreateGroup("optimizations", "Optimizations",
		flagSet.IntVarP(&options.Concurrency, "concurrency", "c", 300, "number of concurrent threads to process"),
		flagSet.IntVar(&options.Timeout, "timeout", 5, "tls connection timeout in seconds"),
		flagSet.IntVar(&options.Retries, "retry", 3, "number of retries to perform for failures"),
		flagSet.StringVar(&options.Delay, "delay", "", "duration to wait between each connection per thread (eg: 200ms, 1s)"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.OutputFile, "output", "o", "", "file to write output to"),
		flagSet.BoolVarP(&options.JSON, "json", "j", false, "display json format output"),
		flagSet.BoolVarP(&options.RespOnly, "resp-only", "ro", false, "display tls response only"),
		flagSet.BoolVar(&options.Silent, "silent", false, "display silent output"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "disable colors in cli output"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "display verbose output"),
		flagSet.BoolVar(&options.Version, "version", false, "display project version"),
	)

	if err := flagSet.Parse(); err != nil {
		return errors.Wrap(err, "could not parse flags")
	}

	if cfgFile != "" {
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			return errors.Wrap(err, "could not read config file")
		}
	}
	return nil
}

func init() {
	// Feature: Debug Mode
	// Errors will include stacktrace when debug mode is enabled
	if os.Getenv("DEBUG") != "" {
		errorutils.ShowStackTrace = true
	}
}
