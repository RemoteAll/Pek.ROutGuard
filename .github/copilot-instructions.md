# Pek.ROutGuard 协作指令（Rust · 双端）

> 组织级通用规范以**用户级指令**（`%APPDATA%\Code\User\prompts\跨项目接续协议.instructions.md`，随 Settings Sync 漫游）为准；本文件只写本仓库特有事实，简体中文回复。

## 项目
- Pek.ROutGuard＝**企业文件防泄漏（DLP）** 双端产品：`pek-outguard-server`（管理端：策略/密钥/终端/审计/审批）+ `pek-outguard-client`（终端：自动加密、受控打开、防退出）。
- Cargo workspace：`core/`（`pek-outguard-core`：容器格式、规则引擎、协议、密钥派生）、`server/`、`client/`。
- Server 面板默认端口 **5600**（可配）；Client 本地 IPC 走命名管道（Windows）/Unix socket（其他平台）。

## 硬性设计口径（改动前必读）
- **加密容器是唯一的对外文件格式**：AES-256-GCM 分块 + 明文头（公司信息/密级/规则/创建者）+ 尾部包裹后的文件密钥。**未装客户端必须打不开**；明文头供"未装客户端时也能看到公司防泄密提示"。
- **密钥不落明文**：Server 主密钥 `Data/master.key`（0600）；客户端策略密钥用机器绑定密钥（Windows DPAPI / Linux 机器密钥文件 0600）包裹后落盘。
- **请求必须签名**：客户端 → 服务端全部请求用设备私钥 Ed25519 签名（含时间戳 + nonce），服务端验签 + 防重放。
- **规则由服务端下发、版本化**：客户端只执行、不本地增删规则；策略版本必须回执（未确认要告警）。
- **性能红线（客户端常驻）**：文件监控按变化驱动 + 去抖（默认 800ms），禁止周期性全盘扫描；心跳默认 60s 且**只发变化项**；审计批量上报（默认 5s 或 200 条）；空闲 CPU < 1%、内存 < 80MB。
- **安全边界必须如实写进文档**：用户态方案不对抗本地管理员 + 内核工具/重装系统；不做进程注入、反杀软、键盘记录。透明驱动（minifilter）属后续可选阶段，需 WDK + 代码签名。

## 复用优先（禁止重复造轮子）
- 日志 `dhrust::logs`；配置 `dhrust::config::TomlConfig`；原子替换 `dhrust::io::safe_replace_file`。
- HTTP 服务/路由/静态资源 `dhrust::net::{http, router, static_files}`；鉴权 `dhrust::net::panel_auth` + `login_guard`；WAF `pek_rwaf`。
- 服务化 `dhrust::service`；星尘注册 `dhrust::staragent`；自升级 `dhrust::upgrade`；增量补丁 `dhrust::patch`。
- ORM/数据库 `pek_rcode`（`database` + `store` + `db_admin`）；管理面数据层 `pek_radmin`。
- 加密原语 `dhrust::secret`（AES-256-GCM）、`dhrust::random`、`dhrust::sign`；包签名 `dhrust::plugin`。
- 进程/系统信息 `dhrust::sys::{process, monitor, machine}`；限流 `dhrust::ratelimit`；审计脱敏 `dhrust::audit`。
- **新增能力前先检索上述模块**；确需新写，先确认没有第二消费方，并在 `docs/架构设计.md` 的复用清单里登记理由。

## 构建与验证
- `cargo check`（日常）/ `cargo test`（每轮收尾）/ `cargo build --release`。
- 依赖为 path：`dhrust=../DH.RustBase`、`pek-rcode=../Pek.RCode`、`pek-radmin=../Pek.RAdmin`、`pek-rwaf=../Pek.RWaf`——**编译报缺 API 时先拉新这些库再复测**。
- 含中文 `.ps1` 必须 UTF-8 with BOM；跑 Python 前设 `$env:PYTHONIOENCODING='utf-8'`。

## 流程
- 每轮收尾**四件套**：① `docs/决策记录.md` 新增节（**含用户原话**）② **审计**（见下）③ `tools/continuity/sync-memory.ps1` 回灌 `docs/项目记忆.md` ④ 回归验证如实汇报（贴实际输出）。
- **每轮必做审计，且必须含安全审计**（2026-10-27 用户原话：「每一轮做完之后要做审计，要包含安全审计」）。产出 `docs/审计报告-<日期>-第N轮.md`，按 `docs/审计报告-2026-10-27-第18轮.md` 第 7 节的**可复用清单**逐项过。硬要求：
  - 审计立场默认「用户态与磁盘内容都是不可信输入」，重点审**谁能改变加密策略**；
  - **遗留风险必须诚实列出，未解决的不许写成已解决**（清单只增不减，解决后才删）；
  - 每轮都要回答：本轮改动**有没有引入写路径**（没有写路径就不可能损坏数据，这是最强的完整性论证）。
- 开工先读：本文件 → `docs/项目接续指南.md` → `docs/用户档案.md` → `docs/项目记忆.md` → 决策最新节 + **最近一份审计报告的"遗留风险"表**。
- GitHub 推送遇 hosts 劫持时用 IP 直连：`git -c http.curloptResolve=github.com:443:<IP> push origin main`。
