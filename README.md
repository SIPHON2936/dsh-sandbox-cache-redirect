# dsh-sandbox-cache-redirect(沙箱缓存重定向插件)

中文 | [English](README.en.md)

一个 DeepSeek Harness(DSH)bundle 插件:安装后,`workspace-write` 受限的 bash 命令会自动把 uv/pip/npm/Go 的缓存与运行时目录写入当前项目,无需逐条命令添加缓存前缀,也不需要提示词层提醒。

> [!IMPORTANT]
> **本项目仅适用于 Linux。** 它依赖 Linux 专有的 bubblewrap(bwrap)沙箱与 user namespace;DSH 在 macOS 和 Windows 上使用完全不同的沙箱后端,本插件在这些平台会直接拒绝加载。已在 Fedora 44(WSL2)实测,详见文末「支持范围」。

## 为什么需要它

DSH 的 workspace-write 模式把宿主根文件系统只读映射,只放开当前工作区和本次命令的 /tmp tmpfs。uv 等工具默认把缓存写入 `~/.cache`(位于只读区),命令因此失败:

```text
Failed to initialize cache at .../.cache/uv
Read-only file system (os error 30)
```

本插件让 DSH 在调用 bwrap 时自动注入工具专用目录变量:缓存、Python 运行时与 Go 状态全部落进项目目录。

## 工作原理

```text
DSH bash executor → sandbox.confine(argv, policy)
  → /usr/bin/python3 -IS <受信 runner> <bwrap profile> -- bash -c <命令>
  → runner 严格匹配 DSH 0.2.1-alpha.2 的 bwrap 模板,在 -- 前注入九个目录变量
  → /usr/bin/bwrap(缓存/运行时落进工作区)
```

本 bundle 做两件事(6.2.1 起为**受检 provider** 结构):

1. **cordis.patch.yml** 停用原生 sandbox 条目并为其附加就绪依赖(若更高配置层把它重新启用,缺少就绪服务会使其无法激活);再插入本包的受检条目。
2. **受检 provider(index.js + lib/)** 继承 Host 的 `LocalSandboxProvider`,把"先校验、后注册、逐次复查"固化进构造与调用路径:
   - **注册前**(prepare):平台/UID 门槛;组合树检查(原生行已停用且就绪依赖在位,bash 行完好);python3/bwrap 双路径身份审计(**含 setuid 位**,先于任何版本查询);bwrap ≥ 0.12.0(CVE-2026-87766 修复下限)与 `python3 -IS` 标志;随包 runner 摘要必须等于 `0ef04d1a…579216`;安装链**逐级先审后建**(拒绝 symlink、组/他人可写、非可信所有者);以**暂存+link 排他发布**原子安装 runner(已存在时仅复用同摘要、本人所有、mode 0500、单链接文件,**绝不覆盖**)。
   - **每次 confine**:复查 runner inode/字节、python/bwrap 身份、实例存活;对 DSH_HOME、DSH 安装、插件包、Python 标准库等 **DUAL 保护树逐跳重走符号链接解析链**,与激活时记录的快照(最终 realpath + 每一跳 link→target)不一致即拒绝;校验本次 mode 与实际会话 root(拒绝 `/`、整个 HOME、含冒号路径,以及与保护集合冲突的工作区布局——保护集合包含解析链上的每个中间链接节点,工作区覆盖其中任一跳即拒绝);委托原生方法生成 argv 后,逐字断言其恰为"固定 runner + 锁定模板 + 原 payload"。
   - 任何失败抛出结构化 `SandboxUnavailableError`——不返回原始命令、不切换本地 executor、不自动提权重试。

任一环节失败,`ctx.sandbox` 根本不会注册:依赖它的受限 bash 执行器不可用,**失败关闭**,而不是退回执行未认证的 runner。runner 本身只做字符串匹配与 exec:不在宿主创建、解析或清理任何缓存目录,不增加挂载;遇到未知 bwrap 模板直接拒绝,不透传为无沙箱命令。

**失败关闭的边界要分清两类故障**:

- **补丁已应用、插件激活失败**(二进制审计不过、runner 摘要不符、组合树被改动等):原生行已被本包补丁停用并挂着就绪依赖,受限命令失败关闭。这是插件代码自身能保证的范围。
- **整个 bundle 被跳过**(bundle 补丁损坏、DSH peer 版本不兼容、包缺失):本包的补丁根本没有应用,插件代码也不会运行,原生行会恢复原样。要让这种情形同样失败关闭,必须把同一行"停用原生 + 就绪依赖"写进 **profile 用户补丁层**(`~/.dsh/profiles/<profile>/cordis.patch.yml`)——该层由 DSH 组合器独立加载,不依赖任何 bundle。随包提供现成片段 `patches/profile-fail-closed.patch.yml`,用法见安装步骤。未应用该片段时,DSH 升级导致的 peer 不兼容会让 bundle 被跳过并**静默回退到原生后端**(bwrap 隔离仍在,但缓存重定向与上述审计全部失效),这不是失败关闭。

provider 行的 config 是严格的:仅接受可选正整数 `probeTimeoutMs` 与可选绝对目录数组 `additionalProtectedRoots`(只能扩大保护集合);`runnerCommand` 等字段一律拒绝——任何配置层都不能把 runner 指向别处。

## 注入的九个目录

| 变量 | 工作区下相对路径 | 用途 |
|---|---|---|
| UV_CACHE_DIR | .dsh-cache/uv | uv 依赖缓存 |
| PIP_CACHE_DIR | .dsh-cache/pip | pip 下载/构建缓存 |
| npm_config_cache | .dsh-cache/npm | npm/npx 缓存及日志 |
| GOCACHE | .dsh-cache/go-build | Go 构建缓存 |
| UV_PYTHON_CACHE_DIR | .dsh-cache/uv-python | managed Python 归档缓存 |
| UV_PYTHON_INSTALL_DIR | .dsh-state/uv/python | 已安装 Python 解释器(持久运行时) |
| UV_PYTHON_BIN_DIR | .dsh-state/uv/bin | managed Python 入口链接 |
| GOMODCACHE | .dsh-cache/go-mod | Go 模块及 sumdb 缓存 |
| GOPATH | .dsh-state/go | sumdb checkpoint 等 Go 状态 |

这些目录由工具在沙箱内自行创建,无需提前在宿主创建。`read-only` 模式原样透传不注入;`danger-full-access` 不经过 runner。

请在项目的 `.gitignore`、`.dockerignore`、打包与备份规则中排除 `.dsh-cache/` 与 `.dsh-state/`:

```gitignore
.dsh-cache/
.dsh-state/
```

## 安装与卸载

### 方式一:dsh 命令一键安装(推荐)

```bash
dsh plugin --profile <你的 profile 名> add github:Siphon2673/dsh-sandbox-cache-redirect
```

该命令把本仓库作为 git 依赖装入指定 profile 并注册 bundle;本包没有构建脚本,不需要 pnpm 的 allowBuilds 豁免。

### 方式二:手动打包安装

```bash
git clone https://github.com/Siphon2673/dsh-sandbox-cache-redirect.git
cd dsh-sandbox-cache-redirect
npm pack           # 生成 dsh-sandbox-cache-redirect-<版本>.tgz
```

然后在 DSH 插件管理器中安装生成的 tgz;也可以直接从 GitHub Release 页面下载已打好的包(由 tag 触发的 release 工作流自动产出)。

两种方式都以拷贝形式落入 profile 的 node_modules,不链接源码目录。

### 第三步(强烈建议):应用 profile 层失败关闭补丁

bundle 自带的补丁只在 bundle 整体加载成功时才应用。为覆盖"整个 bundle 被跳过"的情形(补丁损坏、peer 不兼容、包缺失),把随包片段追加到每个已安装 profile 的用户补丁层末尾:

```bash
cat node_modules/dsh-sandbox-cache-redirect/patches/profile-fail-closed.patch.yml \
  >> ~/.dsh/profiles/<profile 名>/cordis.patch.yml   # 片段本身也是合法 YAML 条目
```

(片段中的注释可保留;只有最后一个 `- id: sandbox` 条目生效所需的映射会被组合器读取。)重启 profile 后生效。应用后,即使 bundle 被整体跳过,原生 sandbox 行仍保持停用,受限命令失败关闭。

卸载/回退(按 profile 核对实际结果,不要笼统假设"恢复内置 bwrap"):

- **临时停用**:在插件管理器中禁用本 bundle。
  - 已应用 profile 层失败关闭补丁的 profile:原生行保持停用,受限命令**失败关闭**(没有可用沙箱),这是预期行为;
  - 未应用该补丁的 profile:原生行恢复启用。注意该行可能被该 profile 的用户补丁层覆盖过 `runnerCommand`(例如历史 V3 方案的覆盖)——此时回退到的是那个覆盖指定的 runner,而不是内置默认 bwrap。回退前请检查 `~/.dsh/profiles/<profile 名>/cordis.patch.yml`,先清理不再信任的旧覆盖。
- **彻底移除**:移除 bundle,并删除上述 profile 补丁条目;原生行恢复为内置 bwrap。`.dsh-state` 中的 Python 解释器可能被项目 venv 引用,请用 uv 自身命令处理,不要直接删除。回退后请用一条受限命令实测确认后端符合预期。

## 验收工具

`tools/` 附带两个独立复验工具(仅用 Python 标准库):

```bash
# 独立 smoke:在宿主直接执行,--parent 用工作区与 /tmp 之外的私有目录
/usr/bin/python3 -IS tools/smoke-v6.py \
  --wrapper "$HOME/.local/libexec/dsh/dsh-bwrap-redirect-v6-0ef04d1a72ad" \
  --parent "$HOME/<私有目录>"
```

smoke 覆盖:九变量注入、宿主可写对照、明确的 EROFS、工作区落盘、/tmp 不回写宿主、read-only 透传/拒写、未知 profile 拒绝执行。

`tools/session-check-v6.py` 用于端到端会话验收:把它复制到私有目录后,在一个全新的 workspace-write 会话中让 agent 通过 bash 工具原样执行(参数含一次性 token 与宿主哨兵路径),它会校验九个变量的取值、工作区写能力和工作区外的 EROFS 拒绝。

## 升级

升级 DSH/bwrap 或更换 runner 时:重新核对 bwrap profile 模板 → 用**新的版本化文件名**与摘要更新本包(`lib/peers.js` 的 `RUNNER_SHA256`、`RUNNER_FILE_NAME`、`PINNED_VERSIONS`,以及 `runner/` 源文件)→ 重跑测试与 smoke 验收 → 重新 `npm pack` 并安装。不要覆盖正在使用的 runner 文件。

runner 对 DSH 的 bwrap 模板做严格匹配,插件入口也把 DSH/sandbox 相关包版本钉死在 `0.2.1-alpha.2`:DSH 升级后本插件会**拒绝加载**。此时若已应用 profile 层失败关闭补丁,原生行保持停用、受限命令失败关闭;若未应用,整个 bundle 被跳过会静默回退到原生后端——按上述流程重验后再放行新版,不要在这种回退状态下继续跑受限命令。

## 支持范围

- 平台:仅 Linux(已在 Fedora 44 WSL2 实测:bwrap 0.12.0、Python 3.14、uv 0.13、Go 1.26)。macOS/Windows 不在支持范围——这两个平台的 sandbox 使用各自后端,本包会直接拒绝加载。
- DSH:严格锁定 0.2.1-alpha.2(bwrap 模板由 runner 逐字匹配,版本由插件入口钉死;其他版本一律拒绝加载)。
- uv 需 ≥ 0.7.0(`UV_PYTHON_CACHE_DIR` 自该版本引入);Go 限 module 模式;工作区路径不接受冒号。
- 不把整个 HOME 或 `/` 当作工作区;runner、DSH_HOME、DSH 安装、插件包、Python 标准库等保护树内不能开项目(每次 confine 逐次检查)。
- 启动目录自由:可以从 `~` 等任意目录启动 `dsh web`;启动 cwd 只是部署默认根,不安全时插件仅记录警告,不影响启动。逐次硬检查针对每个会话的实际工作区根——若把 HOME、`/` 或保护树选作会话工作区,该会话的受限命令会被逐条拒绝并提示改选项目子目录;read-only 会话不受影响。

## 许可证

[MIT](LICENSE)
