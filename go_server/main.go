package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
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

	// 定义一个自定义的 http3.Server
	server := &http3.Server{
		Addr: ":4433",
		Handler: http.DefaultServeMux, // 指定处理器
		QUICConfig: &quic.Config{
			MaxIdleTimeout: time.Second * 3,
		},
	}

	// 启动 HTTP/3 服务器
	log.Println("Starting HTTP/3 server on :4433...")
	err := server.ListenAndServeTLS(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to start HTTP/3 server: %v", err)
	}
}
