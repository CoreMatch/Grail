// Grail 是 HA 生态的产物分发上游：原站 + 分级镜像的混合形态。
//
// 设计稿：/home/lnb/Desktop/HA/GRAIL-DESIGN-20261112.md（R2 定稿）。
// 契约：HA-Contract docs/api/openapi/grail.yaml（METHOD+path 防漂移）。
//
// 子命令：
//   - server  启动节点（root 或 mirror，按配置）
//   - init    初始化原站：生成根密钥与首个密钥环，产出凭据文件模板
//   - admin   原站管理：项目登记（项目密钥）、节点登记（节点身份）、列表
//   - publish 发布产物：上传字节 + 登记版本（含血缘字段）
//   - resolve 解析版本清单并端到端验签
//   - sync    镜像节点执行一次同步（拉取，不推送）
//   - yank / deprecate  撤销 / 宽限期维护
//
// 骨架期仅 server 可运行（路由表已冻结，处理函数 501）。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"Grail/internal/server"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		cmdServer(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "grail: 未知子命令 %q（骨架期仅实现 server）\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `用法: grail <command> [flags]

命令:
  server     启动节点（root 或 mirror）
  init       初始化原站（生成根密钥与凭据模板）
  admin      原站管理（项目/节点登记）
  publish    发布产物
  resolve    解析并验签
  sync       镜像同步一次
  yank       撤销版本
  deprecate  版本置入宽限期
`)
}

func cmdServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:2780", "监听地址")
	fs.Parse(args)

	gin.SetMode(gin.ReleaseMode)
	srv := &http.Server{
		Addr:              *listen,
		Handler:           server.NewRouter(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	fmt.Fprintf(os.Stderr, "grail: listening on %s (skeleton)\n", *listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "grail: %v\n", err)
		os.Exit(1)
	}
}
