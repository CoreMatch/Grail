# Grail

HA 生态的产物分发上游：**原站 + 分级镜像**的混合形态，为各服务提供
`ci` / `candidate` / `release` 三渠道的签名发布物。

- 设计稿：`/home/lnb/Desktop/HA/GRAIL-DESIGN-20261112.md`（R2 定稿，决策记录在其第 17 节）
- 接口契约：HA-Contract `docs/api/openapi/grail.yaml`（METHOD+path 防漂移）
- 部署与操作手册：HRPAuth-Wiki `deploy/grail.md`（部署者视角）与 `dev/grail.md`（开发者视角）

## 形态要点（摘自定稿决策）

- 三渠道：`release`（正式）/ `candidate`（测试）/ `release` 永远来自重建并带血缘，不做指针移动式晋级；
- 默认交付形态是**文件**：对外只给一个规范 URL `GET /{project}/{channel}/{version}/{platform}`，
  本节点托管字节时直供，否则 302；消费方不感知供货方；
- 签名从第一天存在：**每项目一把独立密钥**，根密钥签密钥环；镜像不重签，下游只验原站签名；
- 上下级只靠**下游轮询拉取**，无推送；撤销与宽限状态随同步分发；
- 版本号沿用现有习惯（不透明标识符），渠道判断与解析不依赖版本号数字；
- 清理走宽限期状态机：`active → deprecating(grace) → removed`，yank 与宽限正交。

## 当前状态

骨架期：路由表已按契约冻结（`internal/server/router.go`），处理函数尚未实现（501）。
实现进度见提交历史与 HRPAuth-Wiki 文档。

## 构建

```bash
go build -o grail .
```
