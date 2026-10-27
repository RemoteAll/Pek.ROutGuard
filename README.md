# Pek.ROutGuard

企业内部**文件防泄漏（DLP）**双端产品：

- **Server（管理端）**：终端准入、规则集/策略版本下发、密钥托管、审计、外发审批、卸载授权、Web 面板。
- **Client（终端）**：系统服务常驻、按服务端规则自动加密、受控打开、防关闭/防卸载、事件上报。
- **Driver（内核过滤驱动）**：NTFS minifilter，负责**透明加密**——文件在原地、名字不变、大小不变，
  只有授权的处理进程能读到明文，磁盘上永远是密文。

## 当前技术路线（重要）

产品经历了一次路线收敛，**现在的主线是内核 minifilter 透明加密**：

| 阶段 | 形态 | 状态 |
|---|---|---|
| M1 | 用户态容器（`.ogd`）+ 受控打开 + 自动加密 | ✅ 已完成并实测 |
| ProjFS 安全区 | 用户态虚拟视图 | ⚠️ **已验证不可行**（打开期间明文必落盘），仅保留作演示 |
| **M2** | **minifilter 透明加密（等长 XTS）** | 🚧 进行中（见下） |

minifilter 各里程碑：

| 里程碑 | 内容 | 状态 |
|---|---|---|
| M0 | 驱动骨架、编译/签名/注册、控制通道 | ✅ 编译通过，**未加载验证** |
| M1 | 驱动内规则判定（NT 路径前缀 + 扩展名） | ✅ 编译通过，**未加载验证** |
| M2a | 读 NTFS ADS（`file:oug`）取文件身份 | ✅ 编译通过，**未加载验证** |
| M2b | 内核 SHA-256 校验和验证（防篡改） | ✅ 编译通过，**未加载验证** |
| M2c | XTS 密钥下发通道（BCrypt AES 句柄） | ✅ 编译通过，**未加载验证** |
| M2d | **Read/Write 实际加解密** | ❌ 未实现（用户态参照实现已就绪） |

> ⚠️ **M0~M2c 全部未经运行时验证**（需开启 testsigning 并重启）。
> 验证脚本：`driver/verify.ps1`（八步全自动，含反证与篡改检测）。

## 目录结构

```
core/      pek-outguard-core    容器格式 / XTS / 文件元数据 / 规则引擎 / 协议 / 密钥派生
server/    pek-outguard-server  管理端（Web 面板 + 客户端接口 + 数据库）
client/    pek-outguard-client  终端（服务 + 文件监控 + 加密执行 + 透明加密引擎 + 救援工具）
driver/    minifilter 内核驱动（C，WDK 编译，自签名）
admin/     Tauri 桌面外壳（M2，加载同一套面板）
docs/      需求 / 架构 / 决策记录 / 审计报告 / 接续指南
tools/     接续基建（自检 + 记忆回灌）
```

## 快速开始

```powershell
cargo check                 # 日常检查
cargo test                  # 回归（140 项）
cargo build --release
```

服务端首次启动会生成 `Config/OutGuard.toml` 与 `Data/master.key`，面板默认 `http://127.0.0.1:5600/`。

内核驱动：

```powershell
.\driver\build.ps1          # 编译 + 自动签名（需 VS + WDK）
bcdedit /set testsigning on # 管理员；开启测试签名后需重启
.\driver\install.ps1        # 注册并加载驱动
.\driver\verify.ps1         # 一键验证 M0~M2c
```

救援工具（驱动失效时离线解密）：

```powershell
pek-outguard-client rescue info    <file>            # 查看加密标记
pek-outguard-client rescue decrypt <file> --out DIR  # 解出明文，不动原件
pek-outguard-client rescue scan    <dir> --deep      # 批量体检
```

## 文档

- [需求说明书](docs/需求说明书.md)
- [架构设计](docs/架构设计.md)
- [minifilter 透明加密设计](docs/minifilter透明加密设计.md) —— **当前主线**
- [驱动签名与采购流程](docs/驱动签名与采购流程.md) —— 交付前必读
- [外发审批与外发包设计](docs/外发审批与外发包设计.md)
- [决策记录](docs/决策记录.md) —— 每轮为什么这么做
- [审计报告](docs/) —— 每轮安全审计（`审计报告-<日期>-第N轮.md`）
- [项目接续指南](docs/项目接续指南.md)

## 安全边界（必读）

本产品为**企业管理软件**：目标是防普通员工误传/主动外传、保证受控文件离开授权终端不可读、全链路可审计。

**用户态部分**（容器 / 受控打开 / 自动加密）**不对抗**本地管理员 + 内核工具、PE 修改与重装系统；
不做进程注入、反杀软、键盘记录。

**内核驱动部分**（minifilter 透明加密）由 Windows 内核强制生效，普通进程无法绕过；
但仍**不对抗**本地管理员（管理员可卸载驱动）、不对抗离线攻击（PE/重装系统后文件仍是密文，但可尝试破解），
也不做反调试/反虚拟机。

已知限制（每轮审计持续更新）：见最新一份 `docs/审计报告-*.md` 的"遗留风险"表。
