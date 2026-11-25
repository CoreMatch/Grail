<div align="center">
  <h1>Grail</h1>
  <p><strong>无论从哪里获取，产物字节始终相同。</strong></p>
  <p><a href="./README.md">English</a></p>
</div>

Grail 为 Armorial 生态提供签名产物分发。它向发布者和服务运维人员提供不可变版本与规范 URL，消费方无需关心文件实际存储在哪个节点。

## 为什么选择 Grail

- **按内容寻址。** 内容寻址存储将产物身份与实际存放位置解耦。
- **验证发布者。** Ed25519 签名让消费方检查已签名的发布元数据。
- **区分发布阶段。** `ci`、`candidate` 与 `release` 渠道区分面向不同受众的构建。
- **以拉取方式分发。** 只拉镜像通过拉取获取产物，不依赖推送式复制路径。
- **有序退役版本。** 撤销与弃用状态明确表达撤回和宽限期。

## 进一步了解

- [GitHub 上的 Grail](https://github.com/CoreMatch/Grail) — 规范源码仓库
- [Armorial Grail API 契约](https://github.com/CoreMatch/HA-Contract/blob/main/docs/api/openapi/grail.yaml) — 版本化分发接口
- [服务端路由](internal/server/router.go) — 已注册的 HTTP 接口
- [部署者文档](https://wiki.mcnb.dev/deploy/) — Armorial 运维指引

## 边界

目前没有公共节点，多级镜像、容器同步、构建血缘与真实生产行为尚未得到验证。

## 许可证

[AGPL-3.0](LICENSE)
