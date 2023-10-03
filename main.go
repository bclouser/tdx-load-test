package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/oauth2/clientcredentials"
)

func clusterPrefix(env string) string {
	if env == "prod" {
		return ""
	} else {
		return "." + env
	}
}

// var cluster = "prod"
var cluster = "pilot"
var clusterEnvPrefix = clusterPrefix(cluster)
var serverHost = "https://app" + clusterEnvPrefix + ".torizon.io"
var devicesPackagesUri = serverHost + "/api/v2beta/devices/packages"
var provisionUrl = serverHost + "/api/v2beta/devices"

// gosh, this sucks. CUrrently prod is configured to hand out the root ca for ota-ce, not dgw. Pilot and dev are configured
// to handout dgw. So this script will break across environments :(
// var targetsDeviceGwUrl = "https://ota-ce-" + clusterEnvPrefix[1:] + ".torizon.io:8443/director/targets.json"
var targetsDeviceGwUrl = "https://dgw" + clusterEnvPrefix + ".torizon.io:8443/director/targets.json"
var testUrl = "https://dgw" + clusterEnvPrefix + ".torizon.io:8443/foobar"

var tokenUrl = "https://kc" + clusterEnvPrefix + ".torizon.io/auth/realms/ota-users/protocol/openid-connect/token"

// var tokenUrl = "http://localhost:8081"

func requestDevicesPackages(httpClient *http.Client, index int, wg *sync.WaitGroup) string {
	defer wg.Done() // decrements waitgroup
	req, err := http.NewRequest("GET", devicesPackagesUri, nil)
	if err != nil {
		fmt.Println("Failed to create request")
	}
	startTime := time.Now()
	resp, err := httpClient.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		return fmt.Sprintf("Request %d failed to send. Duration: %d ms Error: %s \n", index, duration.Milliseconds(), err.Error())
	}
	if resp.StatusCode != 200 {
		return fmt.Sprintf("Request %d returned non 200 response: %d in %d ms\n", index, resp.StatusCode, duration.Milliseconds())
	} else {
		return fmt.Sprintf("Request %d completed succesfully in %d ms\n", index, duration.Milliseconds())
	}
	// sb := strings.Builder{}
	// io.Copy(&sb, resp.Body)
	// fmt.Println("Got back: " + sb.String())
}

type CreatedDeviceInfo struct {
	Name       string    `json:"registeredName"`
	DeviceId   string    `json:"deviceID"`
	DeviceUuid string    `json:"deviceUuid"`
	CreatedAt  time.Time `json:"createdAt"`
	PrivateKey *ecdsa.PrivateKey
	DeviceCert x509.Certificate
	RootCert   x509.Certificate
	GatewayUrl string
}

func readFromZip(archive *zip.Reader, filename string) ([]byte, error) {
	file, err := archive.Open(filename)
	if err != nil {
		fmt.Println("Failed to open " + filename + " from device zip archive. Error: " + err.Error())
		return nil, err
	}
	return io.ReadAll(file)
}

func UnzipToDevice(deviceCredentials []byte) (CreatedDeviceInfo, error) {
	zipReader, err := zip.NewReader(bytes.NewReader(deviceCredentials), int64(len(deviceCredentials)))
	if err != nil {
		fmt.Println("Failed to read zipped device reader")
		return CreatedDeviceInfo{}, err
	}

	clientCertPemBytes, err := readFromZip(zipReader, "client.pem")
	if err != nil {
		fmt.Println("Failed to read client.pem from device zip. Error: " + err.Error())
		return CreatedDeviceInfo{}, err
	}
	clientCertPemBlock, _ := pem.Decode(clientCertPemBytes)
	clientCert, err := x509.ParseCertificate(clientCertPemBlock.Bytes)
	if err != nil {
		fmt.Println("Failed to parse device certificate as x509 cert")
		return CreatedDeviceInfo{}, err
	}
	pkeyPemBytes, err := readFromZip(zipReader, "pkey.pem")
	if err != nil {
		fmt.Println("Failed to read pkey.pem from device zip. Error: " + err.Error())
		return CreatedDeviceInfo{}, err
	}
	pkeyPemBlock, _ := pem.Decode(pkeyPemBytes)
	privateKey, err := x509.ParseECPrivateKey(pkeyPemBlock.Bytes)
	if err != nil {
		fmt.Println("Failed to parse ecdsa private key from pem block. Error: " + err.Error())
		return CreatedDeviceInfo{}, err
	}
	rootCertBytes, err := readFromZip(zipReader, "root.crt")
	if err != nil {
		fmt.Println("Failed to read root.cert from device zip. Error: " + err.Error())
		return CreatedDeviceInfo{}, err
	}
	rootCertPemBlock, _ := pem.Decode(rootCertBytes)
	rootCert, err := x509.ParseCertificate(rootCertPemBlock.Bytes)
	if err != nil {
		fmt.Println("Failed to parse x509 root certificate from pem block. Error: " + err.Error())
		return CreatedDeviceInfo{}, err
	}
	gatewayUrlBytes, err := readFromZip(zipReader, "gateway.url")
	if err != nil {
		fmt.Println("Failed to read gateway.url from device zip. Error: " + err.Error())
		return CreatedDeviceInfo{}, err
	}
	infoJsonBytes, err := readFromZip(zipReader, "info.json")
	if err != nil {
		fmt.Println("Failed to read out info.json from device.zip. Error " + err.Error())
		return CreatedDeviceInfo{}, err
	}

	createdDeviceInfo := CreatedDeviceInfo{}
	createdDeviceInfo.DeviceCert = *clientCert
	createdDeviceInfo.PrivateKey = privateKey
	createdDeviceInfo.RootCert = *rootCert
	createdDeviceInfo.GatewayUrl = string(gatewayUrlBytes[:])
	err = json.Unmarshal(infoJsonBytes, &createdDeviceInfo)
	if err != nil {
		fmt.Println("Failed to unmarshal devicezip.info.json into json. Error: " + err.Error())
		return CreatedDeviceInfo{}, err
	}
	return createdDeviceInfo, nil
}

func provisionNewDevice(deviceId string, name string, httpClient *http.Client) (CreatedDeviceInfo, error) {
	// run http request to create device
	// man i am so sick of sending http requests
	body := struct {
		DeviceId   string `json:"deviceId"`
		DeviceName string `json:"deviceName"`
	}{
		deviceId,
		name,
	}

	b, err := json.Marshal(body)
	if err != nil {
		fmt.Println("Failed to marshal device create body into json")
		os.Exit(1)
	}
	req, err := http.NewRequest(http.MethodPost, provisionUrl, bytes.NewReader(b))
	if err != nil {
		fmt.Printf("client: could not create request: %s\n", err)
		os.Exit(1)
	}
	res, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("client: error making provision http request: %s\n", err)
		os.Exit(1)
	}
	buf := bytes.Buffer{}
	io.Copy(&buf, res.Body)

	// fmt.Println("Got back: " + sb.String())
	if err != nil {
		fmt.Println("Failed to read body from response")
	}
	if res.StatusCode > 299 {
		fmt.Println("Provisioning device failed with error: " + res.Status + " body: " + string(buf.Bytes()[:]))
		os.Exit(1)
	}
	return UnzipToDevice(buf.Bytes())
}

func privateKeyToPem(privateKey *ecdsa.PrivateKey) []byte {
	// format as x509 and dump key to file
	privKeyX509Bytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		fmt.Println("Failed to format rsa private key as x509. Error: " + err.Error())
	}
	privateKeyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyX509Bytes,
	}
	return pem.EncodeToMemory(privateKeyBlock)
}

func certificateToPem(cert *x509.Certificate) []byte {
	// format as x509 and dump as pem block into buf
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(certBlock)
}

func getRequestViaDeviceGateway(httpClient *http.Client, url string, device CreatedDeviceInfo, index int, wg *sync.WaitGroup, printResponse bool) (string, string, error) {
	defer wg.Done() // decrements waitgroup

	req, err := http.NewRequest(http.MethodGet, url+"?index="+strconv.Itoa(index), nil)
	if err != nil {
		fmt.Printf("client: could not create request: %s\n", err)
		return "", "", err
	}
	startTime := time.Now()
	res, err := httpClient.Do(req)
	duration := time.Since(startTime)
	if err != nil {
		fmt.Printf("client: error making request to fetch devices through device gateway: %s\n", err)
		return "", "", err
	}
	buf := bytes.Buffer{}
	io.Copy(&buf, res.Body)

	if res.StatusCode > 299 {
		return "", fmt.Sprintf("Request %d failed to get %s Status: %d  in %dms", index, url, res.StatusCode, duration.Milliseconds()), nil
	}

	if printResponse {
		fmt.Println(string(buf.Bytes()[:]))
	}

	return string(buf.Bytes()[:]), fmt.Sprintf("Request %d completed succesfully in %d ms", index, duration.Milliseconds()), nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Specify numRequests as arg 1")
		os.Exit(-1)
	}

	numRequests, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("Unable to parse number of requests from argument 1. Error: " + err.Error())
		os.Exit(-1)
	}

	var wg sync.WaitGroup

	clientId, err := os.ReadFile("/home/bclouser/workspace/toradex/utils/ota_scripts/testing/api-gw/client-" + cluster + ".id")
	if err != nil {
		fmt.Println("Failed to read in clientId. Error: " + err.Error())
		os.Exit(-1)
	}
	clientSecret, err := os.ReadFile("/home/bclouser/workspace/toradex/utils/ota_scripts/testing/api-gw/client-" + cluster + ".secret")
	if err != nil {
		fmt.Println("Failed to read in client secret. Error: " + err.Error())
		os.Exit(-1)
	}

	// https://kc.pilot.torizon.io/auth/realms/ota-users/protocol/openid-connect/token
	fmt.Println("Token Endpoint: " + tokenUrl)

	fmt.Println("Client ID: " + string(clientId[:]))
	fmt.Println("Client Secret: " + string(clientSecret[:]))

	clientIdStr := strings.TrimFunc(string(clientId[:]), func(r rune) bool {
		return !unicode.IsGraphic(r)
	})
	clientSecretStr := strings.TrimFunc(string(clientSecret[:]), func(r rune) bool {
		return !unicode.IsGraphic(r)
	})
	ccConfig := clientcredentials.Config{
		ClientID:     clientIdStr,
		ClientSecret: clientSecretStr,
		TokenURL:     tokenUrl,
		// Scopes:       []string{"profile"},
		// AuthStyle: oauth2.AuthStyleInParams,
	}

	fmt.Println(ccConfig)

	token, err := ccConfig.Token(context.Background())
	if err != nil {
		fmt.Println("Failed to get token. Error: " + err.Error())
		os.Exit(-1)
	}
	fmt.Println("Got token: " + token.AccessToken)

	httpClient := ccConfig.Client(context.Background())
	newDevice, err := provisionNewDevice("apalis-imx6", "", httpClient)
	if err != nil {
		fmt.Println("Failed to provision device. Error: " + err.Error())
		os.Exit(1)
	}
	fmt.Println("Sucessfully provisioned device. " + newDevice.Name)
	fmt.Println("Gateway url is: " + newDevice.GatewayUrl)

	privateKeyPem := privateKeyToPem(newDevice.PrivateKey)
	deviceCertPem := certificateToPem(&newDevice.DeviceCert)
	certChain, err := tls.X509KeyPair(deviceCertPem, privateKeyPem)
	if err != nil {
		fmt.Println("Failed to create certificate chain with device cert and private key. Error: " + err.Error())
		os.Exit(1)
	}

	rootCertPemBytes := certificateToPem(&newDevice.RootCert)
	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(rootCertPemBytes)
	if !ok {
		fmt.Println("Failed to add root ca cert to http client!")
		os.Exit(-1)
	}

	// gotta make a special http client that users our root ca and client cert with mutual tls connection
	clientWMutualTls := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{certChain},
			},
			// DisableKeepAlives: true,
		},
	}

	mux := sync.Mutex{}
	statusMessages := []string{}
	for i := 0; i < numRequests; i++ {
		wg.Add(1)

		// go requestDevicesPackages(httpClient, i, &wg)
		// go getRequestViaDeviceGateway(targetsDeviceGwUrl, newDevice, i, &wg)

		go func(i int) {
			_, statusMsg, err := getRequestViaDeviceGateway(clientWMutualTls, testUrl, newDevice, i, &wg, false)
			mux.Lock()
			if err != nil {
				statusMessages = append(statusMessages, err.Error())
			} else {
				statusMessages = append(statusMessages, statusMsg)
			}
			mux.Unlock()
			return
		}(i)
	}
	wg.Wait()

	for _, msg := range statusMessages {
		fmt.Println(msg)
	}

	// res, err := http.Get(devicesPackagesUri)
	// if err != nil {
	// 	fmt.Printf("error making http request: %s\n", err)
	// 	os.Exit(1)
	// }

	// fmt.Printf("client: got response!\n")
	// fmt.Printf("client: status code: %d\n", res.StatusCode)
}
