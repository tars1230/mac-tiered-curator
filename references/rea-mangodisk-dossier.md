# REA 逆向技术档案：MangoDisk v1.1.0 vs CleanMyMac

## 1. 证据锚点 (REA Evidence Ledger)

| 证据维度 | REA Evidence ID / Manifest | 观测目标与结论 |
| :--- | :--- | :--- |
| **Bundle 清单** | `ev_7e99594c945c5d86b4e41f588488275950e3c08adc4214cfde9c41ea744e116f` | `app.mangodisk.desktop` v1.1.0，Tauri v2 (Rust + Wry/WebKit) 桌面架构 |
| **Artifact 图谱** | `ev_87e354d592d645b9ee87c33f22e1316ba75801a6a4771500c5c5e697c28945c6` (`agm_125aea0e...`) | 无常驻 LaunchDaemon 或后台 Menu 监控进程，纯按需单进程执行 |
| **代码签名与权限** | `ev_c5c56ab70c3f4169483f66074d53e5deaf21778e9062e54f38e0cd55536d263f` | 签名主体：`Developer ID Application: Wangxu Technology Co., Ltd (MDQZTEYSXR)`；`entitlements: null`，Hardened Runtime 开启 |
| **Mach-O 结构与符号** | `ev_e1f6aba18fdd4bddacb6d5c7266e00a736a541c0fe1fb95e869b4b0176d2bb0a` | 包含 4,954 个 `mangodisk_*` Rust 符号、237 条内嵌 TOML 声明式规则，调用 `_getattrlistbulk`、`_lseek`、`_fclonefileat`、`_FSEventStreamCreate`、`_unlinkat` |

---

## 2. MangoDisk 逆向出的核心工程亮点

1. **内核级批量目录扫描 (`0x100ead2ec` `mangodisk_platform::macos::bulk_directory::BulkDirectory::read_page`)**
   - 直接调用 macOS 特有系统调用 `_getattrlistbulk` (`bitmapcount = 5`)，单次内核态切换批量拉取整页目录项的名称、对象类型、修改时间、inode 与实际磁盘分配块大小 (`ATTR_FILE_ALLOCSIZE`)。
2. **稀疏空洞与云盘占位符探测 (`0x100ecaba4` `mangodisk_platform::macos::allocated_content::has_allocated_content`)**
   - 调用 `lseek(fd, 0, SEEK_DATA)` (`whence = 4`)。当返回 `ENXIO (6)` 时判定为无物理数据分配（稀疏文件或未下载云文件），直接跳过哈希与读取，避免触发 iCloud / WebDAV 自动下载。
3. **237 条 Schema v3 声明式清理规则 + 31 种项目构建产物规则 (`0x1007a8924` `parse_current_platform_catalog`)**
   - 覆盖 `ai.*` (`ai.huggingface-xet-cache`)、`app.*` (Claude, ChatGPT, Codex, LM Studio, Ollama, Manus, WorkBuddy, QwenWork, 钉钉, 飞书, 微信, QQ, WPS, 百度网盘)、`dev.*` (uv, bun, pnpm, cargo, go, gradle, rustup, xcode) 及 `project.*` (Rust `target`, Node `node_modules/.next/cache`, Python `.pytest_cache/.mypy_cache/.ruff_cache`, Zig `.zig-cache` 等)。
4. **容器元数据卸载残留识别 (`0x10079c020` `mangodisk_core::applications::leftovers::macos::scan_candidates`)**
   - 解析 `~/Library/Containers/<id>/.com.apple.containermanagerd.metadata.plist` 中的 `MCMMetadataIdentifier` 与 `MCMMetadataInfo -> SandboxProfileDataValidationInfoParameters -> application_bundle`，精确判断原 `.app` 是否已被移除。
5. **事务级 Universal Binary 瘦身 (`0x1009372c0` `macos_universal_binaries::platform::execute`)**
   - 先通过 `_fclonefileat` 做 APFS 写时复制零拷贝备份，剥离非原生架构切片后依次调用：
     - `0x10093baa8` `verify_bundle`: `/usr/bin/codesign --verify --deep --strict <bundle>`
     - `0x10093be6c` `assess_gatekeeper`: `/usr/sbin/spctl --assess --type execute <bundle>`
   - 一旦任一校验失败，立即调用 `0x10093b3dc` (`rollback_transaction`) 无损还原。
6. **10 项原生系统维护 (`0x100ee63d8` `mangodisk_platform::macos::system_maintenance::scan`)**
   - 包含 `dns-cache`、`quicklook-cache`、`launch-services`、`icon-cache`、`finder-service`、`audio-service`、`user-permissions`、`legacy-overrides`、`startup-disk`、`spotlight-index`。
