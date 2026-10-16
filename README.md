# dsh-sandbox-cache-redirect

中文 | [English](README.en.md)

DSH（DeepSeek Harness）沙箱缓存重定向插件（V7 可插拔方案，Linux）。

为 workspace-write 受限命令把 uv/pip/npm/Go 的缓存与运行时目录重定向进项目内，解决沙箱内默认缓存位置不可写导致的工具失败，无需逐条命令加缓存前缀。**本版是可插拔架构：增强只存在于本 bundle 的补丁层；停用或卸载后，DSH 按其他有效配置层恢复原生沙箱，无需任何手工清理。**

## 为什么需要它

DSH 的 workspace-write 模式把宿主根文件系统只读映射，只放开当前工作区和本次命令的 /tmp tmpfs。uv 等工具默认把缓存写入 `~/.cache`（位于只读区），命令因此失败：

```text
Failed to initialize cache at .../.cache/uv
Read-only file system (os error 30)
```

本插件让 DSH 在调用 bwrap 时自动注入工具专用目录变量：缓存、Python 运行时与 Go 状态全部落进项目目录。

## 工作原理

```text
bash / GUI PTY / 其他同服务域消费者
  → sandbox.confine(payload, policy, signal)
  → 原生 LocalSandboxProvider 选择后端并生成 argv（bwrap → Landlock 回退）
  → 选中 bwrap 时，在载荷前的 "--" 处插入九个环境选项；其他后端原样透传
  → DSH 原有 subprocess/PTY 执行、取消与错误分类
```

注入的九个变量：

| 变量 | 项目内相对路径 |
|---|---|
| `UV_CACHE_DIR` | `.dsh-cache/uv` |
| `PIP_CACHE_DIR` | `.dsh-cache/pip` |
| `npm_config_cache` | `.dsh-cache/npm` |
| `GOCACHE` | `.dsh-cache/go-build` |
| `UV_PYTHON_CACHE_DIR` | `.dsh-cache/uv-python` |
| `UV_PYTHON_INSTALL_DIR` | `.dsh-state/uv/python` |
| `UV_PYTHON_BIN_DIR` | `.dsh-state/uv/bin` |
| `GOMODCACHE` | `.dsh-cache/go-mod` |
| `GOPATH` | `.dsh-state/go` |

缓存根取自本次调用的会话工作区根（canonical 路径），与命令 cwd 无关。这些目录由工具在沙箱内自行创建；插件不在宿主提前 mkdir，不新增可写挂载，不修改 Host 的 `process.env`、PATH、HOME 或任何配置。

## 状态合同

| 状态 | 行为 |
|---|---|
| 未安装 / 停用 / 已卸载 / 整包被 DSH 跳过 | 本插件配置层退出；恢复其他配置决定的原生 provider；不残留任何就绪依赖或补丁 |
| Linux + workspace-write + 原生选择 bwrap + 布局合格 | 自动注入完整九变量，原生挂载与载荷原样保留 |
| Linux + workspace-write + 原生选择 Landlock | 原生结果原样返回；每个 provider 实例对该降级明确告警一次；**不宣称缓存重定向已启用**（uv 等命令仍可能因默认缓存不可写而失败） |
| read-only | 原生结果原样返回，不注入，也不报增强失效告警 |
| danger-full-access | 正常由 DSH 消费者绕过 confine；直接低层调用本 provider 传入此 mode 会被拒绝 |
| 未知 mode、危险工作区、原生返回结构不兼容、实例已撤销 | 本次调用明确失败（失败关闭），不返回原始 argv，不切换无沙箱执行 |
| bwrap 与 Landlock 均不可用 | 原生 SandboxUnavailableError 原样抛出 |
| 配置字段错误或预期布局无法解析 | provider 保留注册；Linux workspace-write 按调用拒绝并给出修复路径；read-only 不受这些增强错误影响 |
| 工作区根含冒号（如 `/data/proj:ect`） | 布局检查仍生效；因 Unix GOPATH 冒号分隔语法无法表达，**整组增强跳过**、原生隔离保持、按实例告警一次（与 6.x 直接拒绝该工作区不同） |

## 能力边界（相对 6.x 的有意收缩）

- **不校验 bwrap 二进制身份。** 本版沿用 DSH 原生 PATH 解析与功能探针；旧版对 bwrap/python 的属主、setuid/setgid、可写位与整条执行信任链的审计保证**不再保留**。Host 启动环境、安装件与 PATH 必须受信。
- **环境可见性收缩。** 插件只能枚举调用时 Host `process.env` 中已存在的规范键及大小写别名（别名在沙箱内 unset 后以规范键设置工作区值）。仅由 `spec.env`/`spec.dshEnv` 新增、Host 从未见过的大小写别名无法被枚举，仍可能进入沙箱并影响工具配置；这类自定义调用的完整重定向不作保证。规范键本身无论是否在 Host 环境中都会被设为工作区值（bwrap 在沙箱启动前执行 argv 中的环境选项，原生环境清洗不会撤销仍保留在 argv 中的选项）。
- 不再包含外置 Python runner、安装器、runner 摘要校验与 profile 层失败关闭补丁。
- 非 Linux 平台不承诺缓存增强：加载本包时按原生 provider 透传，并提示不支持。

保留的防护：一次性只读部署布局采集（HOME、DSH_HOME、Host/插件/Node 路径与 PATH 上的 bwrap 候选）把 Host 代码与配置域记为保护树/保护节点，工作区根与之双向重叠或覆盖时按调用拒绝。该项只防止工作区覆盖 Host 依赖，**不能替代**已删除的二进制身份审计。

## 配置

本行仅支持两个字段：

- `probeTimeoutMs`：正整数。显式值优先；未配置时继承同树原生 sandbox 行配置中的普通正整数值；两者皆无则使用已核对 SDK 默认值（5000）。
- `additionalProtectedRoots`：可解析的绝对目录数组。每个条目按保护树处理（拒绝工作区等于它、位于其内部或覆盖它），始终与内置保护集合**合并**（只能扩大、不能缩小），不产生额外可写挂载。

**有效类型与取值要求以本节业务校验合同为准；`--dump-config-schema` 与管理器配置界面显示的是宽接收层（any），不作为业务类型依据，any 不表示什么值都能执行。**

错误处理：未知字段、无效 `probeTimeoutMs`、非数组/相对路径/不存在/非目录/无法解析的 `additionalProtectedRoots` 条目，以及预期布局采集失败，都会记录为配置/布局错误状态（日志标签 `CACHE_REDIRECT_CONFIG` / `CACHE_REDIRECT_LAYOUT`，标明条目、字段、下标与原因）。此时 provider 仍注册，read-only 调用不受影响，Linux workspace-write 调用被精确拒绝并提示修复路径：**修正本行配置/目录后重载或重启，或停用本 bundle 恢复原生**。修正配置后重载（重建实例）即恢复。

## 启用、停用、卸载与恢复

- **有管理器界面（web）**：用 DSH bundle 开关停用/启用；按返回的 `applied` / `restart-required` 生效（restart-required 需重启）。停用后原生沙箱即恢复，无需编辑任何 YAML。
- **卸载**：`dsh plugin --profile <p> remove dsh-sandbox-cache-redirect`。依赖与选择由管理器一并撤销。
- **无 GUI 的 profile（如 headless）**：停止该 profile 的 Host 并备份后，可用包内离线选择脚本切换启用状态（只改 bundle 选择，不删依赖、不改 YAML）：
  ```bash
  node ~/.dsh/profiles/<p>/node_modules/dsh-sandbox-cache-redirect/tools/bundle-selection.mjs \
    "$(command -v dsh)" ~/.dsh/profiles/<p> disable   # 重新启用: enable
  ```
  脚本尊重该 profile 已有的精确版本豁免，不自动授予或修改豁免。保存选择后重启该 profile 并用 `--dump-config` 核对。
- **构造/导入失败的恢复**：管理平面可用时用管理器停用本 bundle；不可用时停止 Host 后用上述离线脚本撤销选择，再启动即为原生配置。不需要手工删除 YAML。

注意：已经启动的进程、后台任务与 PTY 保留创建时的环境与隔离；停用不会逆向修改它们。需要完全切换时，正常结束旧任务并关闭/重建持久终端。

## 支持范围

- 平台：Linux（本版增强仅在 Linux + workspace-write + bwrap 链路上生效）。
- 已验证环境：Fedora 44（WSL2）、DSH 0.2.1-alpha.2、Node 24、bwrap 0.12.0；npm 形态的 DSH CLI/Host。打包 Electron、其他启动器与远程执行器未验证。
- peer 声明保持保守：仅声明已实际验证的版本；DSH 升级后须按兼容流程重新验收再扩大范围。运行时不再做固定版本字符串判等，改为按调用的结构契约（载荷尾部、selectedRunner 形状、元数据），不兼容时按调用失败关闭。
- GOPATH 为源码模式的项目、依赖宿主自定义 GOPATH 的项目不承诺兼容；插件不设置 GOSUMDB=off，不修改 GOPROXY/GOTOOLCHAIN/GOFLAGS。

## 项目侧提示：.gitignore

如果你在某个 Git 项目中使用本插件，请在该项目根的 `.gitignore` 中保留原有规则并追加：

```gitignore
/.dsh-cache/
/.dsh-state/
```

缓存与本机下载的运行时不宜提交到项目仓库；`.dsh-state` 中的 Python 还可能被现有 venv 引用。忽略规则不会取消已跟踪文件，此类情况按项目自身流程处理。插件不会自动改写 `.gitignore`、不执行 `git rm`；停用或卸载时也不删除这些运行时目录。

## 从 6.x 迁移

6.x 的旧方案包含外置 runner 与 profile 层失败关闭补丁，卸载后原生沙箱不会自动恢复。迁移到 7.x 必须按顺序执行：停止相关 Host → 经 `dsh plugin remove` 卸载旧包 → 从各 profile 的 `cordis.patch.yml` 中精确移除旧门禁条目（`id: sandbox` 且带 `sandboxCacheRedirectGuardReady` 注入的那一条，保留用户其他设置）→ 删除旧专用 runner（`~/.local/libexec/dsh/dsh-bwrap-redirect-v6-*`；`~/.local/bin/dsh-bwrap-redirect` 这类 V3 历史文件按引用情况另行处理）→ 启动 Host 验证原生基线（受限 bash 可用、隔离保持）→ 再安装 7.x。详细步骤与验收顺序见施工方案第 10 节。

## 验收

交付包含同版可运行验收脚本：`tools/session-check.py`（真实受限会话内运行：九变量、工作区写入、工作区外哨兵拒写、后端挂载证据与 token 标记；`--expect native` 用于原生基线验收）与 `tools/bundle-selection.mjs`（无 GUI profile 的离线启停）。测试套件：`node --test tests/*.test.mjs`（需本机安装 DSH CLI，或用 `DSH_CLI=/path/to/dsh` 指定锚点）。

许可：MIT。
