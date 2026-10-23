---
name: mac-tiered-curator
description: >-
  macOS 四层多盘冷热治理与 AI 开发者精巧清理技能（融合 MangoDisk v1.1.0 逆向精华与 CleanMyMac 优势特性）。
  当用户询问清理磁盘、释放空间、/Volumes/Cache 满了、修复失效软链接、瘦身 AI Agent 状态库（Codex/Hermes/OpenClaw/WorkBuddy）、
  清理项目构建产物、查找应用卸载残留或执行 macOS 系统维护时使用。
---

# mac-tiered-curator 🧭

专为本机 **四层多盘存储架构 (`/System/Volumes/Data` + `/Volumes/Cache` + `/Volumes/databox` + `/Volumes/archive`)** 与 **重度 AI Agent 工作流 (`Codex` / `Hermes` / `OpenClaw` / `WorkBuddy` / `Cline` / `OpenCode` / `Antigravity`)** 量身定制的空间治理与冷热分层技能。

它不仅融合了通过 REA 逆向 `/Applications/MangoDisk.app` (v1.1.0) 提取的内核级安全清理规则与 CleanMyMac 的维护特性，更重要的是将 **“清理”升维为“删除纯缓存 + 向 `/Volumes/archive` 冷兜底盘无损归档迁移 + 跨层软链跟随重绑”** 的完整四层生命周期闭环：
- **纯缓存直接删 (`clean`)**：穿透跨盘软链接清空内部纯缓存与滚动日志，100% 保留软链拓扑。
- **冷资产迁往兜底盘 (`archive`)**：对低频/不确定是否还会用到的历史目录、冷备份、大体积安装包执行 **`move+symlink`（迁入 `/Volumes/archive` 并原位留软链）** 或 **`move_cold`（纯冷归档落盘）**，自动校验文件数与字节一致性，自动感知 `ExFAT` vs `APFS` 内部软链兼容性，并在 `/Volumes/archive/from-databox/app/archives/_manifests/` 生成可追溯 JSON 账本。
- **跨盘迁移后软链自愈 (`fix-symlinks`)**：自动追踪从 `DataPool` / `databox` 迁入 `/Volumes/archive/from-databox` 的目标并原子重绑。

---

## 核心工作流

设 `$SKILL_DIR` 为本技能所在目录（如 `~/.shared/skills/mac-tiered-curator` 或项目根目录）。

### 1. 全景态势、缓存清理与冷归档候选项诊断（默认只读，秒级输出）

```bash
python3 "$SKILL_DIR/scripts/curator.py" scan
```

该命令一次性完成 8 项只读诊断：
1. **四层多盘水位态势**：检查系统盘 (`/System/Volumes/Data`)、高速缓存盘 (`/Volumes/Cache`)、热数据盘 (`/Volumes/databox`)、冷兜底归档盘 (`/Volumes/archive`) 的实时容量与健康告警。
2. **Symlink-Aware 纯缓存扫描**：按物理卷汇总可直接清理的纯缓存，自动标记 `🔗[软链穿透保护]`。
3. **Cold-Tier Archive 兜底盘冷迁移扫描**：按源物理卷汇总可无损迁往 `/Volumes/archive`（或含内部 POSIX 软链时自动路由至 `/Volumes/databox` APFS）的冷备份、历史工作区与旧安装包。
4. **AI Agent SQLite 状态库碎片分析**：使用只读 URI 模式检测 `~/.hermes/state.db`、`~/.codex/logs_2.sqlite` 等数据库的 `freelist_count` 可回收体积。
5. **多跳悬空软链接诊断**：扫描 `~`、`~/Desktop`、`~/Downloads`、`~/Applications`、`~/Library/Application Support` 下因旧盘退役或归档迁移导致的失效软链接，自动匹配 `/Volumes/databox` 与 `/Volumes/archive/from-databox` 中的真实路径。
6. **项目 Marker 陈旧构建产物扫描**：基于 `Cargo.toml`、`package.json`、`pyproject.toml` 等标志文件查找超过 7 天未修改的构建产物。
7. **沙盒容器卸载残留**：解析 `~/Library/Containers/*/.com.apple.containermanagerd.metadata.plist` 揪出已卸载应用的孤儿容器。
8. **Universal Binary 瘦身评估**：扫描 `/Applications` 下可剥离 `x86_64` 切片的双架构应用。

### 2. 安全清理纯缓存规则（保留跨盘软链拓扑）

```bash
# 预览（Dry-Run，不删任何文件）
python3 "$SKILL_DIR/scripts/curator.py" clean --rules safe_defaults

# 确认后执行清理（自动保留软链接本身，仅清空目标内部缓存项）
python3 "$SKILL_DIR/scripts/curator.py" clean --rules safe_defaults --apply
```

### 3. 向 `/Volumes/archive` 兜底盘执行无损冷迁移归档（`move+symlink` / `move_cold`）

```bash
# 预览所有可迁往冷兜底盘的候选项及目标路径（Dry-Run）
python3 "$SKILL_DIR/scripts/curator.py" archive --rules all

# 确认后执行冷迁移（rsync 校验无误后删源、原位生成软链，并写入 _manifests 账本）
python3 "$SKILL_DIR/scripts/curator.py" archive --rules all --apply
```

### 4. 一键重绑或清理悬空失效软链接

```bash
# 预览可自动重绑到 /Volumes/databox 或 /Volumes/archive/from-databox 的软链接
python3 "$SKILL_DIR/scripts/curator.py" fix-symlinks

# 确认后原子重绑（加 --remove-orphans 可同时移除无替代目标的死链）
python3 "$SKILL_DIR/scripts/curator.py" fix-symlinks --apply
```

### 5. 执行逆向自 MangoDisk 的 macOS 原生维护指令

```bash
python3 "$SKILL_DIR/scripts/curator.py" maint
python3 "$SKILL_DIR/scripts/curator.py" maint --task quicklook-cache --apply
```

### 6. 一键执行五步定期维护例程（`routine`）

集成了「1. 五层多盘水位快照（含 `123pan` WebDAV 零遍历挂载巡检与自愈） $\rightarrow$ 2. 跨盘断链自愈 $\rightarrow$ 3. 安全缓存清理 + `*.BundleMigration` 与 Cursor `agent-cli`/`CachedData`/`logs` N-keep-2 多版本轮转（带软链激活版本锁定保护） $\rightarrow$ 4. AI Agent SQLite 无损 `VACUUM` $\rightarrow$ 5. 冷数据向 `/Volumes/archive` / `/Volumes/databox` 归档落盘」的幂等自动化入口：

```bash
# 预览整套定期维护例程（Dry-Run）
python3 "$SKILL_DIR/scripts/curator.py" routine

# 执行定期维护并输出最新报告至 logs/routine_latest.json
python3 "$SKILL_DIR/scripts/curator.py" routine --apply
```

---

## 安全红线（必须遵守）

1. **绝不遍历网络/云挂载目录**：通过 macOS 内核 `libc.statfs` (`MNT_LOCAL` & `f_fstypename`) 与目录名双重拦截 WebDAV/SMB/NFS 及 `~/CloudMounts`。
2. **外置盘挂载态门禁（`os.path.ismount`）**：向 `/Volumes/archive` 或 `/Volumes/databox` 归档前强制校验外置卷处于真实挂载状态，绝不在外置盘拔出时误写根盘 `/Volumes/<disk>` 占位目录；同名归档目标自动追加时间戳后缀防覆盖。
3. **能冷归档兜底的绝不盲删**：凡属低频历史工作目录、镜像备份、旧版安装包，优先通过 `archive` (`move+symlink` / `move_cold`) 迁入 931GB 的 `/Volumes/archive` 兜底盘，实现热盘腾退 + 零数据丢失。
4. **软链拓扑零破坏**：对软链接目录执行 `clean` 时严禁 `unlink` 软链接本身；对含内部 POSIX 软链的目录执行 `archive` 时自动感知 `ExFAT` 限制并路由至 `APFS` 归档区。
5. **先预览后执行**：任何带 `--apply` 的操作前，必须先核对 dry-run 明细。
6. **逆向技术细节参考**：需要查阅 MangoDisk v1.1.0 的 REA 逆向证据链与底层实现时，读取 [references/rea-mangodisk-dossier.md](./references/rea-mangodisk-dossier.md)。

