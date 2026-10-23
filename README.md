# mac-tiered-curator 🧭

> **English**: Safe, tiered multi-volume disk curation & AI Agent workstation hygiene for macOS. Synthesizes kernel-level safety rules reverse-engineered from MangoDisk v1.1.0 and CleanMyMac. Diagnoses, auto-heals symlinks, prunes versioned runtimes, and safely archives cold data with parity verification. Adapts seamlessly from single-disk laptops to 4-tier workstations.
>
> **中文**：专为 macOS 开发者与重度多 AI Agent（Cursor / Codex / Hermes / WorkBuddy / Cline / OpenCode / Antigravity）工作站量身打造的**四层多盘冷热空间治理与无损清理技能**。融合 MangoDisk v1.1.0 逆向精华与 CleanMyMac 运维特性，推翻传统清理软件「rm -rf 盲删打断软链」的弊端，实现**安全纯缓存清理 + 多版本运行时轮转 + 跨盘失效断链自愈 + 冷资产迁入兜底盘**的全生命周期闭环。

---

## 🌟 为什么需要它？（推翻传统清理软件的 3 大误区）

主流商业清理软件在面对现代多 AI Agent 开发者工作站时，常常造成灾难性后果：

| 传统清理工具的粗暴做法 | 真实引发的系统灾难 | `mac-tiered-curator` 的工程解决方案 |
| :--- | :--- | :--- |
| **盲目 `rm -rf` 整个缓存目录** | 一把梭删掉软链接本身，直接打断开发者跨盘链接拓扑（如 `~/Library/Caches/ms-playwright -> /Volumes/Cache/...` 变成死链，导致后续工具链完全挂掉）。 | **🔗 软链拓扑穿透保护**：深度感知符号链接，清理时只清空内部纯缓存与滚动日志，100% 保留软链接真身与目标根节点。 |
| **「一键清空」不给任何后悔药** | 很多旧版本安装包、历史 trace、归档工程虽然很久没用，但仍可能需要回滚或溯源，盲删导致资产永久灭失。 | **🧊 冷兜底安全网 (`archive`)**：将“删除”升维为“冷热分流”。对低频资产执行 `move+symlink`（迁入大容量冷盘并原位留软链）或 `move_cold`，搬迁前后校验文件数与字节一致性，并落盘可追溯 JSON 账本。 |
| **对网络盘/网盘高并发盲扫** | 将 WebDAV、SMB、NFS 挂载当本地盘扫，导致网络拥堵、触发云存储高频 API 风控甚至被封号。 | **🛡️ 内核 `statfs` 物理卷守卫**：直接通过 macOS 内核 `libc.statfs`（校验 `MNT_LOCAL` 标志与文件系统类型），零遍历屏蔽任何网络与虚拟挂载点。 |

---

## 🧭 四层架构设计：新机器最佳配置实践建议

代码在启动时会自动探测挂载点。无论您是**单盘轻便笔记本**，还是**专业四层多盘工作站**，系统都能智能适配最佳策略：

```
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 0: 系统高速盘 (/System/Volumes/Data - 内置 NVMe SSD)               │
│ 作用：操作系统、活跃环境 (~/.shared, ~/basic-memory)、日常工作区         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ 自动软链引流 / 超期冷数据迁出
┌───────────────────────────────────▼────────────────────────────────────┐
│ Tier 1: 高速暂存盘 (/Volumes/Cache - 高速雷电/USB4 外置 SSD, APFS)     │
│ 作用：纯缓存、包管理器 Wheels (uv/npm/pip)、Playwright 浏览器、编译中间件│
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ 历史工程 / 稳定产物归档
┌───────────────────────────────────▼────────────────────────────────────┐
│ Tier 2: 热数据与工程盘 (/Volumes/databox - 大容量外置 SSD, APFS)        │
│ 作用：活跃的大型工程、媒体源片、需要保留内部 POSIX 符号链接的归档        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ 超期低频资产兜底 (Move + Parity Check)
┌───────────────────────────────────▼────────────────────────────────────┐
│ Tier 3: 冷兜底归档盘 (/Volumes/archive - 1TB~4TB 移动硬盘, ExFAT/APFS)   │
│ 作用：历史冷备份、大安装包镜像、旧 traces；每次迁入必出 SHA/Count 账本   │
└────────────────────────────────────────────────────────────────────────┘
```

### 💡 针对不同硬件配置的适配指南

#### 1. 单盘模式（MacBook Air / Pro 纯内置 SSD）
- **适配逻辑**：无需任何外接盘。`curator.py` 会聚焦执行：
  - 核心纯缓存安全清理（包括 Cursor ShipIt 更新包、OpenCode 桌面下载包、浏览器 CRX 缓存等）；
  - Playwright、Cursor agent-cli、WorkBuddy BundleMigration 的 **N-keep-K 多版本自动轮转**；
  - AI Agent SQLite 数据库的无损 `VACUUM` 空闲页压缩。
- **冷归档适配**：未检测到 `/Volumes/archive` 时，冷归档阶段会自动跳过并给出友好提示，绝不影响纯缓存清理与系统体检。若需在单盘下启用归档，只需指定环境变量 `export CURATOR_ARCHIVE_ROOT="$HOME/Archives"`。

#### 2. 双盘模式（内置 SSD + 1 块外接移动硬盘）
- **推荐做法**：外接盘格式化为 **APFS**，卷名命名为 `databox` 或 `archive`。
- **环境变量一键指定**：
  ```bash
  export CURATOR_ARCHIVE_ROOT="/Volumes/MyExternalDrive/archives"
  ```

#### 3. 终极四层模式（Mac Studio / Mac Mini 重度工作站）
- **推荐命名与文件系统组合**：
  - `/Volumes/Cache`：格式化为 **APFS**（高速、小文件密集写入、支持克隆）；
  - `/Volumes/databox`：格式化为 **APFS**（保留内部 POSIX 软链与 Git 仓库兼容性）；
  - `/Volumes/archive`：格式化为 **ExFAT**（跨系统可读、大容量机械盘/便宜 SSD 即可胜任。注意：`curator.py` 内置了 ExFAT 感知逻辑，若待归档目录包含内部软链接，会自动智能降级分流至 APFS 的 databox，防止跨文件系统软链损坏）。

---

## ⚡ 快速开始

```bash
# 1. 克隆技能库
git clone https://github.com/tars1230/mac-tiered-curator.git
cd mac-tiered-curator

# 2. 全景只读诊断（五层水位 + 可清理缓存 + SQLite 碎片 + 悬空软链 + 陈旧构建产物）
python3 scripts/curator.py scan

# 3. 预览五步例行维护（Dry-Run 模式，不触碰任何文件）
python3 scripts/curator.py routine

# 4. 一键执行五阶段幂等例程维护（确认无误后执行）
python3 scripts/curator.py routine --apply
```

### 常用独立子命令

```bash
# 仅清理默认安全纯缓存（100% 保留软链接拓扑）
python3 scripts/curator.py clean --rules safe_defaults --apply

# 自动轮转修剪 Playwright 废弃 Chromium 内核版本（默认保留最新 1 个）
python3 scripts/curator.py routine --apply

# 修复因盘符更换或路径变迁导致的失效多跳软链接
python3 scripts/curator.py fix-symlinks --apply

# 对膨胀的 AI Agent SQLite 数据库做无损 VACUUM（空闲碎片 >= 10MB 时才收缩）
python3 scripts/curator.py vacuum-sqlite --min-reclaim-mb 10 --apply

# 逆向自 MangoDisk 的 macOS 维护动作（如清理 QuickLook 缩略图缓存）
python3 scripts/curator.py maint --task quicklook-cache --apply
```

---

## 🛡️ 安全模型与防护铁律

1. **绝对禁止集（Strict Denial Guard）**：
   - 严禁触碰 `/System`、`/Library` 核心资产；
   - 严禁将用户的 `~/Documents`、`~/Desktop`、`~/Pictures`、`~/Movies` 等私人工作区当作缓存清理。
2. **符号链接穿透审计（Dual-Path Validation）**：
   - 不仅校验逻辑路径，还通过 `os.path.realpath` 解析物理真身路径，确保源端与目标端均在受控白名单范围内。
3. **真实挂载态门禁（`os.path.ismount`）**：
   - 任何向 `/Volumes/<disk>` 写入冷归档的动作前，强制检查目标卷处于活跃挂载态，绝不在外接盘断开时向本地根盘写入虚假占位目录。
4. **归档校验与审计账本**：
   - 每次迁移完成前后核对文件总数（剔除 macOS 自动生成的 `.DS_Store` / `._*` AppleDouble 干扰）；
   - 在 `_manifests` 目录下生成包含文件数、字节数、时间戳的防篡改 JSON 账本，随时可按账本原样回滚。

---

## 🧪 单元测试

项目包含完备的自动化回归测试套件，全面覆盖路径安全边界、软链原子替换、SQLite 空闲页分析、Playwright 轮转及冷归档校验：

```bash
python3 tests/test_curator.py
# Ran 19 tests in 0.2s - OK
```

---

## 📄 License

[MIT License](LICENSE)
