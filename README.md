# dsh-sandbox-cache-redirect(沙箱缓存重定向插件)

把《DSH 沙箱缓存与运行时目录重定向实施手册 V6.2》固化为一个 DSH bundle:安装后,`workspace-write` 受限的 bash 命令自动把 uv/pip/npm/Go 的缓存与运行时目录写入当前项目,无需逐条命令加缓存前缀,也不需要提示词层提醒。

## 工作原理

```
DSH bash executor → sandbox.confine(argv, policy)
  → /usr/bin/python3 -IS <受信 runner> <bwrap profile> -- bash -c <命令>
  → runner 严格匹配 DSH 0.2.1-alpha.2 的 bwrap 模板,在 -- 前注入九个目录变量
  → /usr/bin/bwrap(缓存/运行时落进工作区)
```

本 bundle 做两件事:

1. **cordis.patch.yml** 整体替换 sandbox 条目(`@deepseek-ai/dsh-sandbox-local`)的 config:
   `runnerCommand` 指向受信 runner,`runnerFailureSignatures` 登记其故障方言,`probeTimeoutMs` 5000。
2. **index.js(Host 插件)** 在激活时按手册 §5 语义安装 runner:
   - 校验随包 runner 的 SHA-256(必须等于 `0ef04d1a…579216`);
   - 排他创建 `$HOME/.local/libexec/dsh/dsh-bwrap-redirect-v6-0ef04d1a72ad`,mode 0500,`O_NOFOLLOW`;
   - 已存在时仅复用同摘要、本人所有、无组/他人写权限的常规文件,**绝不覆盖**;
   - 复核安装件摘要与权限位,审计父目录链(每级须 root 或本人所有、不可被组/他人写);
   - 前置门槛:仅 Linux;`/usr/bin/python3`、`/usr/bin/bwrap` 可执行;bwrap ≥ 0.12.0(CVE-2026-87766 修复下限)。

任何一步失败,插件加载即抛错;此时 runnerCommand 指向的文件不可用,sandbox **失败关闭**(命令不会无沙箱运行),而不是悄悄退化。

## 注入的九个目录(手册 §2.2)

| 变量 | 工作区下相对路径 |
|---|---|
| UV_CACHE_DIR | .dsh-cache/uv |
| PIP_CACHE_DIR | .dsh-cache/pip |
| npm_config_cache | .dsh-cache/npm |
| GOCACHE | .dsh-cache/go-build |
| UV_PYTHON_CACHE_DIR | .dsh-cache/uv-python |
| UV_PYTHON_INSTALL_DIR | .dsh-state/uv/python |
| UV_PYTHON_BIN_DIR | .dsh-state/uv/bin |
| GOMODCACHE | .dsh-cache/go-mod |
| GOPATH | .dsh-state/go |

`read-only` 模式原样透传不注入;`danger-full-access` 绕过 runner。请在项目的 `.gitignore`、`.dockerignore`、打包与备份规则中排除 `.dsh-cache/` 与 `.dsh-state/`。

## 安装与卸载

```bash
# 打包(产物拷入 profile,不链接工作区,满足信任链要求)
pnpm pack          # 生成 dsh-sandbox-cache-redirect-6.2.0.tgz
```

然后用插件管理器(`plugin_manager install_bundle`)把 tgz 装入目标 profile。

卸载/回退(等效于手册 §10.2 的配置回退):
- 临时停用:`plugin_manager set_bundle`(disabled)——sandbox 配置还原为内置 bwrap 选择,runner 文件保留不删;
- 彻底移除:`plugin_manager remove_bundle`;`.dsh-state` 中的解释器仍可能被项目 venv 引用,按需用 uv 自身命令处理。

## 验收(手册 §6/§8 的工具随包附在 tools/)

```bash
# 独立 smoke(宿主执行,--parent 用工作区与 /tmp 外的私有目录)
/usr/bin/python3 -IS tools/smoke-v6.py \
  --wrapper "$HOME/.local/libexec/dsh/dsh-bwrap-redirect-v6-0ef04d1a72ad" \
  --parent "$HOME/<私有目录>"

# 会话验收:把 tools/session-check-v6.py 复制到私有目录后,
# 在「全新 workspace-write 会话」里通过 bash 工具原样执行(见手册 §8)。
```

## 升级纪律(手册 §11)

升级 DSH/bwrap 或更换 runner 时:重新核对 profile 模板 → 使用**新版本化文件名**和摘要更新本包(index.js 的 `RUNNER_SHA256`、`RUNNER_FILE_NAME` 与 cordis.patch.yml 的路径一并改)→ 重跑 smoke 与完整回归 → 重新打包安装。不得覆盖正在使用的 runner 文件。

## 支持范围

Linux(手册以 Fedora 44 WSL2 记录为参考);DSH 0.2.1-alpha.2 的 bwrap 模板被 runner 严格锁定——DSH 升级后模板变化会被 runner 拒绝(`unrecognized bwrap profile`),须按升级纪律重验。macOS/Windows 不在本包支持范围(这两个平台 sandbox 使用各自后端,本包会直接拒绝加载)。
