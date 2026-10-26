# Pek.ROutGuard

企业内部**文件防泄漏（DLP）**双端产品：

- **Server（管理端）**：终端准入、规则集/策略版本下发、密钥托管、审计、外发审批、卸载授权、Web 面板。
- **Client（终端）**：系统服务常驻、按服务端规则自动加密、已授权终端受控解密打开、防关闭/防卸载、事件上报。

## 目录结构

```
core/      pek-outguard-core    容器格式 / 规则引擎 / 协议 / 密钥派生
server/    pek-outguard-server  管理端（Web 面板 + 客户端接口 + 数据库）
client/    pek-outguard-client  终端（Windows 服务 + 文件监控 + 加密执行）
docs/      需求说明书 / 架构设计 / 决策记录 / 项目接续
tools/     接续基建（自检 + 记忆回灌）
```

## 快速开始

```powershell
cargo check                 # 日常检查
cargo test                  # 回归
cargo build --release
```

服务端首次启动会生成 `Config/OutGuard.toml` 与 `Data/master.key`，面板默认 `http://127.0.0.1:5600/`。

## 文档

- [需求说明书](docs/需求说明书.md)
- [架构设计](docs/架构设计.md)
- [决策记录](docs/决策记录.md)
- [项目接续指南](docs/项目接续指南.md)

## 安全边界（必读）

本产品为**企业管理软件**：目标是防普通员工误传/主动外传、保证受控文件离开授权终端不可读、全链路可审计。
用户态方案**不对抗**本地管理员 + 内核工具、PE 修改与重装系统；不做进程注入、反杀软、键盘记录。
