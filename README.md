# dsh-sandbox-cache-redirect(沙箱缓存重定向插件)

中文 | [English](README.en.md)

一个 DeepSeek Harness(DSH)bundle 插件:安装后,`workspace-write` 受限的 bash 命令会自动把 uv/pip/npm/Go 的缓存与运行时目录写入当前项目,无需逐条命令添加缓存前缀,也不需要提示词层提醒。

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

本 bundle 做两件事:

1. **cordis.patch.yml** 整体替换 sandbox 条目(`@deepseek-ai/dsh-sandbox-local`)的 config:
   `runnerCommand` 指向受信 runner,`runnerFailureSignatures` 登记其故障方言,`probeTimeoutMs` 5000。
2. **index.js(Host 插件)** 在激活时安装并核验 runner:
   - 校验随包 runner 的 SHA-256(必须等于 `0ef04d1a…579216`);
   - 排他创建 `$HOME/.local/libexec/dsh/dsh-bwrap-redirect-v6-0ef04d1a72ad`,mode 0500,`O_NOFOLLOW`;
   - 已存在时仅复用同摘要、本人所有、无组/他人写权限的常规文件,**绝不覆盖**;
   - 复核安装件摘要与权限位,审计父目录链(每级须 root 或本人所有、不可被组/他人写);
   - 前置门槛:仅 Linux;`/usr/bin/python3`、`/usr/bin/bwrap` 可执行;bwrap ≥ 0.12.0(CVE-2026-87766 修复下限)。

任何一步失败,插件加载即抛错;此时 runnerCommand 指向的文件不可用,sandbox **失败关闭**(命令不会无沙箱运行),而不是悄悄退化。

runner 本身只做字符串匹配与 exec:不在宿主创建、解析或清理任何缓存目录,不增加挂载;遇到未知 bwrap 模板直接拒绝,不透传为无沙箱命令。

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
dsh plugin --profile <你的 profile 名> add github:SIPHON2936/dsh-sandbox-cache-redirect
```

该命令把本仓库作为 git 依赖装入指定 profile 并注册 bundle;本包没有构建脚本,不需要 pnpm 的 allowBuilds 豁免。

### 方式二:手动打包安装

```bash
git clone https://github.com/SIPHON2936/dsh-sandbox-cache-redirect.git
cd dsh-sandbox-cache-redirect
npm pack           # 生成 dsh-sandbox-cache-redirect-<版本>.tgz
```

然后在 DSH 插件管理器中安装生成的 tgz;也可以直接从 GitHub Release 页面下载已打好的包(由 tag 触发的 release 工作流自动产出)。

两种方式都以拷贝形式落入 profile 的 node_modules,不链接源码目录。

卸载/回退:

- 临时停用:在插件管理器中禁用本 bundle——sandbox 还原为内置 bwrap 后端,runner 文件保留;
- 彻底移除:移除 bundle。`.dsh-state` 中的 Python 解释器可能被项目 venv 引用,请用 uv 自身命令处理,不要直接删除。

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

升级 DSH/bwrap 或更换 runner 时:重新核对 bwrap profile 模板 → 用**新的版本化文件名**与摘要更新本包(`index.js` 的 `RUNNER_SHA256`、`RUNNER_FILE_NAME`,`cordis.patch.yml` 的 runnerCommand 路径,以及 `runner/` 源文件)→ 重跑 smoke 验收 → 重新 `npm pack` 并安装。不要覆盖正在使用的 runner 文件。

runner 对 DSH 的 bwrap 模板做严格匹配;DSH 升级导致模板变化时,受限命令会失败关闭并报 `unrecognized bwrap profile`,此时按上述流程重验。

## 支持范围

- 平台:仅 Linux(已在 Fedora 44 WSL2 实测:bwrap 0.12.0、Python 3.14、uv 0.13、Go 1.26)。macOS/Windows 不在支持范围——这两个平台的 sandbox 使用各自后端,本包会直接拒绝加载。
- DSH:0.2.1-alpha.2 的 bwrap 模板被 runner 严格锁定。
- uv 需 ≥ 0.7.0(`UV_PYTHON_CACHE_DIR` 自该版本引入);Go 限 module 模式。

## 许可证

[MIT](LICENSE)
