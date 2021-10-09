/*
 * AWS Credentials Proxy by Golang.
 *
 * @author    yasutakatou
 * @copyright 2021 yasutakatou
 * @license   3-clause BSD License
 */
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crt "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"
	"yasutakatou/goCred/winctl"

	"github.com/taglme/string2keyboard"
)

type encryptCredData struct {
	Label      string
	Cred       string
	Expiration string
}

type credJsonData struct {
	Type            string `json:"type"`
	AccessKeyId     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	Token           string `json:"token"`
	Expiration      string `json:"expiration"`
	Code            string `json:"code"`
}

type requestData struct {
	Token string `json:"token"`
}

type responseData struct {
	Token      string `json:"token"`
	Expiration string `json:"expiration"`
}

var (
	debug, logging, linux bool
	Token                 string
	Cloudshell            string
	encryptCred           []encryptCredData
	rs1Letters            = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	targetHwnd            uintptr
	tryCounter            int
	waitSeconds           int
	countDown             int
)

type (
	HANDLE uintptr
	HWND   HANDLE
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	_debug := flag.Bool("debug", false, "[-debug=debug mode (true is enable)]")
	_server := flag.Bool("server", false, "[-server=Server mode (true is enable)]")
	_proxy := flag.Bool("proxy", false, "[-proxy=Proxy mode (true is enable)]")
	_port := flag.String("port", "8080", "[-prort=Port Number (Use Proxy mode)]")
	_cert := flag.String("cert", "localhost.pem", "[-cert=ssl_certificate file path]")
	_key := flag.String("key", "localhost-key.pem", "[-key=ssl_certificate_key file path]")
	_token := flag.String("token", "", "[-token=authentication token (if this value is null, is set random)]")
	_client := flag.Bool("client", false, "[-client=Client mode (true is enable)]")
	_Logging := flag.Bool("log", false, "[-log=logging mode (true is enable)]")
	_Cloudshell := flag.String("cloudshell", "CloudShell", "[-cloudshell=AWS Cloudshell window titile]")
	_try := flag.Int("try", 100, "[-try=error and try counter]")
	_countDown := flag.Int("count", 60, "[-count=operating interval ]")
	_wait := flag.Int("wait", 250, "[-wait=loop wait Millisecond]")

	flag.Parse()

	Cloudshell = string(*_Cloudshell)
	debug = bool(*_debug)
	logging = bool(*_Logging)
	tryCounter = int(*_try)
	countDown = int(*_countDown)
	waitSeconds = int(*_wait)

	if *_client == true && *_token == "" {
		fmt.Println("client mode must set token! {-token}")
		os.Exit(1)
	}

	if *_token == "" {
		Token = RandStr(8)
	} else {
		Token = string(*_token)
	}

	if *_server == false && *_client == false && *_proxy == false {
		fmt.Println("not defined run mode.. {-server | -proxy | -client}")
		os.Exit(1)
	}

	if *_server == true || *_client == true {
		if len(flag.Args()) == 0 {
			fmt.Println("not defined Access IP and Port.. {ex. 192.168.0.1:8080}")
			os.Exit(1)
		}
	}

	if *_server == true {
		debugLog("token: " + Token)
		serverStart(flag.Args()[0], Token)
	} else if *_proxy == true {
		proxyStart(*_port, *_cert, *_key)
	} else {
		if runtime.GOOS == "linux" {
			debugLog("OS: Linux")
			linux = true
		} else if runtime.GOOS == "windows" {
			debugLog("OS: Windows")
			linux = false
		} else {
			fmt.Println("Error: not support this os.")
			os.Exit(-1)
		}
		clientStart(flag.Args()[0], Token)
	}
	os.Exit(0)
}

func getAWSCred() (string, string, string, string) {
	awsToken := os.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN")
	awsCred := os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")

	request, _ := http.NewRequest("GET", awsCred, nil)
	request.Header.Set("Authorization", awsToken)

	//request, _ := http.NewRequest("GET", "http://192.168.0.12:3000/", nil)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tr,
	}
	resp, err := client.Do(request)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var result credJsonData
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Println("auth error: token is incorrect?")
		log.Fatal(err)
	}
	return result.AccessKeyId, result.SecretAccessKey, result.Token, result.Expiration
}

func getServer(ip, token string) string {
	if strings.Index(ip, "https://") == -1 {
		ip = "https://" + ip + "/get"
	}

	request, err := http.NewRequest(
		"POST",
		ip,
		bytes.NewBuffer(JsonToByteReq(requestData{Token: token})),
	)

	if err != nil {
		log.Fatal(err)
	}

	request.Header.Set("Content-Type", "application/json")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
	}
	resp, err := client.Do(request)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var result responseData
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Println("auth error: token is incorrect?")
		log.Fatal(err)
	}

	decodes, err := decrypt(result.Token, []byte(addSpace(token)))
	if err == nil {
		crypt := strings.Split(decodes, "\t")
		writeCredential(crypt[0], crypt[1], crypt[2])
		debugLog("cred update ok!")
	}
	return result.Expiration
}

func writeCredential(aws_access_key_id, aws_secret_access_key, aws_session_token string) {
	user, err := user.Current()
	if err != nil {
		log.Fatalf(err.Error())
		return
	}
	homeDirectory := user.HomeDir

	var configFile string
	if linux == true {
		configFile = homeDirectory + "/.aws/credentials"
	} else {
		configFile = os.Getenv("USERPROFILE") + "\\.aws\\credentials"
	}

	if Exists(configFile) == true {
		const layout = "2006-01-02_15"
		t := time.Now()
		if err := os.Rename(configFile, configFile+"_"+t.Format(layout)); err != nil {
			fmt.Println(err)
			return
		}
	}

	file, err := os.OpenFile(configFile, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	_, err = file.WriteString("[default]\n")
	_, err = file.WriteString("region = ap-northeast-1\n")
	_, err = file.WriteString("output = json\n")
	_, err = file.WriteString("aws_access_key_id = " + aws_access_key_id + "\n")
	_, err = file.WriteString("aws_secret_access_key =" + aws_secret_access_key + "\n")
	_, err = file.WriteString("aws_session_token = " + aws_session_token + "\n")
}

func clientStart(ip, token string) {
	expiration := getServer(ip, token)
	t, _ := time.Parse(time.RFC3339Nano, expiration)
	diff := t.Unix() - int64(countDown/2)
	count := 0
	for {
		now := time.Now()
		if now.Unix() >= diff {
			expiration = getServer(ip, token)
			t, _ = time.Parse(time.RFC3339Nano, expiration)
			diff = t.Unix() - int64(countDown/2)
		}
		time.Sleep(time.Second * time.Duration(1))
		count = count + 1
		if count > (countDown * 3) {
			fmt.Println("IP: " + ip + " Token: " + token + " Expiration: " + expiration)
			count = 0
			if linux == false {
				setHwnd := winctl.GetWindow("GetForegroundWindow", debug)
				if targetHwnd := winctl.FocusWindow(Cloudshell, debug); winctl.ChangeTarget(targetHwnd, tryCounter, waitSeconds, debug) == false {
					fmt.Println("AWS CloudShell Window not found!")
					os.Exit(1)
				}
				string2keyboard.KeyboardWrite("\\n")
				time.Sleep(time.Duration(waitSeconds) * time.Millisecond)
				winctl.SetActiveWindow(winctl.HWND(setHwnd), debug)
			}
		}
	}
}

func serverStart(ip, token string) {
	aws_access_key_id, aws_secret_access_key, aws_session_token, expiration := getAWSCred()
	t, _ := time.Parse(time.RFC3339Nano, expiration)
	diff := t.Unix() - int64(countDown)

	pingData, err := encrypt(aws_access_key_id+"\t"+aws_secret_access_key+"\t"+aws_session_token, []byte(addSpace(string(token))))

	debugLog("cred: " + aws_access_key_id + "\t" + aws_secret_access_key + "\t" + aws_session_token)
	sendServer(ip, token, pingData, expiration)
	if err != nil {
		fmt.Println("error: ", err)
		os.Exit(1)
	}

	count := 0
	for {
		now := time.Now()
		if now.Unix() >= diff {
			aws_access_key_id, aws_secret_access_key, aws_session_token, expiration = getAWSCred()

			pingData, err := encrypt(aws_access_key_id+"\t"+aws_secret_access_key+"\t"+aws_session_token, []byte(addSpace(string(token))))

			debugLog("cred: " + aws_access_key_id + "\t" + aws_secret_access_key + "\t" + aws_session_token)
			sendServer(ip, token, pingData, expiration)
			if err != nil {
				fmt.Println("error: ", err)
				os.Exit(1)
			}

			t, _ = time.Parse(time.RFC3339Nano, expiration)
			diff = t.Unix() - int64(countDown)
		}
		time.Sleep(time.Second * time.Duration(1))
		count = count + 1
		if count > (countDown * 3) {
			fmt.Println("IP: " + ip + " Token: " + token + " Expiration: " + expiration)
			count = 0
		}
	}
}

func JsonToByteReq(data requestData) []byte {
	outputJson, err := json.Marshal(data)
	if err != nil {
		return []byte(fmt.Sprintf("%s", err))
	}
	return []byte(outputJson)
}

func JsonToByte(data encryptCredData) []byte {
	outputJson, err := json.Marshal(data)
	if err != nil {
		return []byte(fmt.Sprintf("%s", err))
	}
	return []byte(outputJson)
}

func sendServer(ip, token, pingData, expiration string) {
	if strings.Index(ip, "https://") == -1 {
		ip = "https://" + ip + "/put"
	}

	request, err := http.NewRequest(
		"POST",
		ip,
		bytes.NewBuffer(JsonToByte(encryptCredData{Label: token, Cred: pingData, Expiration: expiration})),
	)

	if err != nil {
		log.Fatal(err)
	}

	request.Header.Set("Content-Type", "application/json")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
	}
	resp, err := client.Do(request)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	debugLog(string(body))
}

func debugLog(message string) {
	var file *os.File
	var err error

	if debug == true {
		fmt.Println(message)
	}

	if logging == false {
		return
	}

	const layout = "2006-01-02_15"
	t := time.Now()
	filename := "goTrust_" + t.Format(layout) + ".log"

	if Exists(filename) == true {
		file, err = os.OpenFile(filename, os.O_WRONLY|os.O_APPEND, 0666)
	} else {
		file, err = os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0666)
	}

	if err != nil {
		log.Fatal(err)
		return
	}
	defer file.Close()
	fmt.Fprintln(file, message)
}

func Exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func proxyStart(port, cert, key string) {
	http.HandleFunc("/get", getHandler)
	http.HandleFunc("/put", putHandler)

	go func() {
		for {
			fmt.Printf(".")
			time.Sleep(time.Second * time.Duration(1))
		}
	}()

	err := http.ListenAndServeTLS(":"+port, cert, key, nil)
	if err != nil {
		log.Fatal("ListenAndServeTLS: ", err)
	}
}

func putHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if debug == true {
		fmt.Println("put call: ", r.RemoteAddr, r.URL.Path)
	}

	d := json.NewDecoder(r.Body)
	p := &encryptCredData{}
	err := d.Decode(p)
	if err != nil {
		w.Write([]byte("internal server error"))
		return
	}

	resp := changeToken(p)

	data := &responseData{Token: resp}
	outputJson, err := json.Marshal(data)
	if err != nil {
		fmt.Println("%s")
		return
	}

	w.Write(outputJson)
}

func changeToken(token *encryptCredData) string {
	for x, cred := range encryptCred {
		if cred.Label == token.Label {
			encryptCred[x].Label = token.Label
			encryptCred[x].Cred = token.Cred
			encryptCred[x].Expiration = token.Expiration
			return token.Label + " changed"
		}
	}

	encryptCred = append(encryptCred, encryptCredData{Label: token.Label, Cred: token.Cred, Expiration: token.Expiration})
	return token.Label + " add"
}

func getHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if debug == true {
		fmt.Println("get call: ", r.RemoteAddr, r.URL.Path)
	}

	d := json.NewDecoder(r.Body)
	p := &requestData{}
	err := d.Decode(p)
	if err != nil {
		w.Write([]byte("internal server error"))
		return
	}

	token, expiration := searchToken(p.Token)

	data := &responseData{Token: token, Expiration: expiration}
	outputJson, err := json.Marshal(data)
	if err != nil {
		fmt.Println("%s")
		return
	}

	w.Write(outputJson)
}

func searchToken(token string) (string, string) {
	for _, cred := range encryptCred {
		if cred.Label == token {
			return cred.Cred, cred.Expiration
		}
	}
	return "", ""
}

// FYI: https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go
func getIFandIP() (string, string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return iface.Name, ip.String(), nil
		}
	}
	return "", "", errors.New("are you connected to the network?")
}

// FYI: http://www.inanzzz.com/index.php/post/f3pe/data-encryption-and-decryption-with-a-secret-key-in-golang
// encrypt encrypts plain string with a secret key and returns encrypt string.
func encrypt(plainData string, secret []byte) (string, error) {
	cipherBlock, err := aes.NewCipher(secret)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(crt.Reader, nonce); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(plainData), nil)), nil
}

// decrypt decrypts encrypt string with a secret key and returns plain string.
func decrypt(encodedData string, secret []byte) (string, error) {
	encryptData, err := base64.URLEncoding.DecodeString(encodedData)
	if err != nil {
		return "", err
	}

	cipherBlock, err := aes.NewCipher(secret)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	nonceSize := aead.NonceSize()
	if len(encryptData) < nonceSize {
		return "", err
	}

	nonce, cipherText := encryptData[:nonceSize], encryptData[nonceSize:]
	plainData, err := aead.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainData), nil
}

func addSpace(strs string) string {
	for i := 0; len(strs) < 16; i++ {
		strs += "0"
	}
	return strs
}

func RandStr(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = rs1Letters[rand.Intn(len(rs1Letters))]
	}
	return string(b)
}
