// demo-service 是 Grail runbook 与端到端验证用的最小服务：
// 一个带 /healthz 的 HTTP 进程，可被 Deployer 经 Tinyvisor 编排。
// 它不是产品组件，只服务于"发布 → 同步 → 部署"闭环的可复现验证。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

// version 在构建时以 -ldflags "-X main.version=..." 注入；
// 缺省读环境变量 DEMO_VERSION，再缺省为 unknown。
var version = ""

func main() {
	port := flag.Int("port", 0, "监听端口（缺省读环境变量 PORT，再缺省 8090）")
	flag.Parse()

	if version == "" {
		version = os.Getenv("DEMO_VERSION")
	}
	if version == "" {
		version = "unknown"
	}
	if *port == 0 {
		if p := os.Getenv("PORT"); p != "" {
			fmt.Sscanf(p, "%d", port)
		}
		if *port == 0 {
			*port = 8090
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"service": "grail-demo-service",
			"version": version,
		})
	})

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	log.Printf("demo-service %s listening on %s", version, addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
