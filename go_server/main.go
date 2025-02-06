package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/quic-go/quic-go/http3"
)

func main() {
	// 设置一个简单的 HTTP Handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World")
	})

	// 配置 TLS 证书（HTTP/3 必须使用 TLS）
	certFile := "server.crt" // 替换为实际的证书文件路径
	keyFile := "server.key"  // 替换为实际的私钥文件路径

	// 启动 HTTP/3 服务器
	log.Println("Starting HTTP/3 server on :4433...")
	err := http3.ListenAndServeTLS(":4433", certFile, keyFile, nil)
	if err != nil {
		log.Fatalf("Failed to start HTTP/3 server: %v", err)
	}
}
