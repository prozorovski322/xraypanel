package sublink_test

import (
	"fmt"

	"github.com/xraypanel/panel/internal/sublink"
)

// Example output is verified by `go test`, so these double as documentation that cannot
// drift from the code.

func ExampleEndpoint_URI_reality() {
	endpoint := sublink.Endpoint{
		Remark:      "DE-1 Berlin",
		Address:     "de1.example.com",
		Port:        443,
		Protocol:    sublink.ProtocolVLESS,
		Transport:   sublink.TransportTCP,
		Security:    sublink.SecurityReality,
		UUID:        "8c3a1f92-5d7e-4b21-9f44-2e6b0c1d8a37",
		Flow:        "xtls-rprx-vision",
		SNI:         "www.cloudflare.com",
		Fingerprint: "chrome",
		PublicKey:   "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
		ShortID:     "0123456789abcdef",
	}

	uri, err := endpoint.URI()
	if err != nil {
		panic(err)
	}
	fmt.Println(uri)
	// Output:
	// vless://8c3a1f92-5d7e-4b21-9f44-2e6b0c1d8a37@de1.example.com:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&security=reality&sid=0123456789abcdef&sni=www.cloudflare.com&type=tcp#DE-1%20Berlin
}

func ExampleEndpoint_URI_websocket() {
	endpoint := sublink.Endpoint{
		Remark:    "CDN",
		Address:   "cdn.example.com",
		Port:      8443,
		Protocol:  sublink.ProtocolVLESS,
		Transport: sublink.TransportWS,
		Security:  sublink.SecurityTLS,
		UUID:      "8c3a1f92-5d7e-4b21-9f44-2e6b0c1d8a37",
		SNI:       "cdn.example.com",
		ALPN:      []string{"h2", "http/1.1"},
		Path:      "/ws",
		Host:      "cdn.example.com",
	}

	uri, err := endpoint.URI()
	if err != nil {
		panic(err)
	}
	fmt.Println(uri)
	// Output:
	// vless://8c3a1f92-5d7e-4b21-9f44-2e6b0c1d8a37@cdn.example.com:8443?alpn=h2%2Chttp%2F1.1&encryption=none&host=cdn.example.com&path=%2Fws&security=tls&sni=cdn.example.com&type=ws#CDN
}

// ExampleEndpoint_URI_shadowsocks shows the SIP002 shape for a 2022 method: userinfo in
// clear, percent encoded, with the server key and the user key joined by a colon.
func ExampleEndpoint_URI_shadowsocks() {
	endpoint := sublink.Endpoint{
		Remark:      "SS",
		Address:     "ss.example.com",
		Port:        8388,
		Protocol:    sublink.ProtocolShadowsocks,
		SSMethod:    "2022-blake3-aes-128-gcm",
		SSServerKey: "YctPZ6U7xPPcU+gp3u+0tw==",
		SSUserKey:   "tx/tRizJN9K8y+uKlW2qjg==",
	}

	uri, err := endpoint.URI()
	if err != nil {
		panic(err)
	}
	fmt.Println(uri)
	// Output:
	// ss://2022-blake3-aes-128-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tw%3D%3D%3Atx%2FtRizJN9K8y%2BuKlW2qjg%3D%3D@ss.example.com:8388#SS
}

func ExampleUserInfo_UserInfoHeader() {
	info := sublink.UserInfo{
		Upload:   1 << 30,
		Download: 5 << 30,
		Total:    100 << 30,
	}
	fmt.Println(info.UserInfoHeader())
	// Output:
	// upload=1073741824; download=5368709120; total=107374182400; expire=0
}

func ExampleExpandTemplate() {
	ctx := sublink.TemplateContext{Username: "alice", NodeName: "de-1", Country: "DE"}

	fmt.Println(sublink.ExpandTemplate("{COUNTRY} {NODE}", ctx))
	fmt.Println(sublink.ExpandTemplate("{USERNAME}@{NODE}", ctx))
	// A placeholder that does not exist is left visible rather than blanked.
	fmt.Println(sublink.ExpandTemplate("{NDOE}", ctx))
	// Output:
	// DE de-1
	// alice@de-1
	// {NDOE}
}

func ExampleFormatFor() {
	for _, agent := range []string{
		"v2rayNG/1.8.23",
		"mihomo/1.18.1",
		"SFI/1.9.0 (239; sing-box 1.8.9)",
		"curl/8.4.0",
	} {
		fmt.Printf("%-34s %s\n", agent, sublink.FormatFor(agent))
	}
	// Output:
	// v2rayNG/1.8.23                     base64
	// mihomo/1.18.1                      clash
	// SFI/1.9.0 (239; sing-box 1.8.9)    singbox
	// curl/8.4.0                         base64
}
