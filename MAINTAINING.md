# Peters ChatGPT MCP Server — 长期维护与开发入口指南

本文面向未来接手维护或按需修复的全新 Agent 与操作者，提供一页式权威基线、安全边界、测试、构建、部署与回滚指引。

---

## 1. 当前唯一正式稳定基线

| 项 | 值 |
| --- | --- |
| 正式版本 / Tag | **`v0.5.5`**（冻结源码提交 `b20a5891e3b5047cd6fc261f28223004de84fee0`） |
| 正式源码目录 | `versions/0.5.5/` |
| `source_content_fingerprint` | `4e3c3373183594de9599035c128198a96d6899b252bef060f9d534e1b39e56c3` |
| `candidate_fingerprint`（生产包） | `66d641052da882a1aa96f4b4dcbf476322336298416e0cbbd0cfc35d60f9ca9b` |
| `rollback_fingerprint`（检查用） | `b20c3b5ff288d795f042a3ccab02839afe89a3182386ceefec0a25f56b17e739` |
| 依赖锁定文件 | `versions/0.5.5/requirements.lock`（Python 3.12 / macOS arm64 验证） |
| 历史实验线（勿用于生产） | 根目录 `peters_mcp/`（`0.6.0`）仅为早期独立实验线，保留供查阅 |

> **冻结原则**：绝不原地修改已发布的 `versions/0.5.5/` 及其 `BUILD_SPEC.json` 内文件，以保证 Tag `v0.5.5` 与现网运行包指纹永久可复现。任何新版本修复须复制派生新版本目录（如 `versions/0.5.6/`）并通过独立分支 + PR 进入 `main`。

---

## 2. 产品目标与核心安全边界

1. **统一 `v2` 项目白名单**：新增一个目录或已校验 Git 仓库后，同一已认证客户端可访问该项目的文件浏览/搜索/读取、有效 worktree、候选 Markdown（需客户端写确认）以及所有已启用历史来源的归属可核实公开会话；撤销项目或添加 `denied_threads` 后立即全路径 fail-closed。
2. **四来源只读会话核验**：
   - **Codex**：支持普通 `paginated`/inline 分叉截断前文重建、附属会话与派生子 Agent 自身公开视图隔离、原生工具元数据多 Agent 通知过滤（完整保留字面 `<subagent_notification>` 文本）、`.jsonl.zst` 压缩日志；缺少可核实归属证据的旧会话默认隔离（fail-closed）。
   - **Antigravity Desktop（2.32.1 / 2.33+）**：DB + `transcript_full.jsonl` 双轨核验、Checkpoint 压缩步骤恢复、子 Agent 同源隔离、协作式有界步骤让出（适配 macOS `ProcessType=Background` 后台 QoS）、四组物理戳绑定缓存与受控路径迁移。
   - **Codeg 0.45.0**：支持已核验的 `codex` / `deepseek`（链接去重）及 Codeg 自有 ACP v1（`zcode`、`trae`、`command_code`、`minimax_code`、`custom:*`）；未支持的 `agent_type` 通过 `unsupported_agent_types` 诚实披露。
   - **DeepSeek Harness**：只读公开消息投影与损坏头诚实降级。
3. **文件写入与原件导出边界**：
   - 候选 Markdown（`prepare_candidate` / `save_candidate`）仅新建不覆盖，且强制经过客户端写确认。
   - 原生文件保存（`save_generated_file`）与原件/分片导出（`export_file`、`raw-parts-v1`）默认关闭，须按主机私有配置显式启用。当服务以 `--file-inspection-only` 且 `original-files` 配置中 `enabled=false` 运行时，`get_write_capabilities` 返回 `inspection_only=true, write_enabled=false, readiness_reason="file_writes_disabled"`（历史字段名 `mode="rollback_inspection_only"` 表示只读检视态，不代表运行回滚包），属预期安全边界。
4. **公开仓库隐私红线**：
   - 严禁向 Git 提交任何本机个人绝对路径、真实业务项目 ID/标题/会话正文、真实域名/隧道 ID、凭据/Token/私钥、`__pycache__` 或主机私有验收回执。
   - 公开测试与 CI 一律只使用合成数据。

---

## 3. 日常故障定位顺序

1. **确认运行版本与监听状态**：使用操作主机上的 `release_cutover.py status` 核对 `runtime/manifest.json` 指纹、活跃进程 PID 与认证门 HTTP `401`，确认无 `__pycache__` 污染 `runtime/`。
2. **确认统一策略与权限范围**：在只读条件下核查策略代际与 `agent_history_admin lint` / `preview-coverage`，排查是否为项目撤权、路径迁移未核准、物理身份变更或 `denied_threads` 导致的 fail-closed。
3. **检查工作进程健康与审计日志**：查看主机私有 `remote-audit.jsonl` 与 LaunchAgent `stderr.log`，区分 `processing`（正常续查）、`processing_timeout` / `restart_required`（单步超时或进程重启，需发新请求不带旧游标）与 `unauthorized`。
4. **隔离复现**：一律在 `/private/tmp` 克隆策略副本 + `/usr/sbin/taskpolicy -b` 复现后台 QoS 行为，不直接拿辅助进程打开在线服务正在锁定的 `serving-v2/scratch`。

---

## 4. 回归测试、构建、独立验收与发布回滚

### 4.1 运行全量合成回归测试

```sh
cd versions/0.5.5
python3.12 -B -m unittest discover -s tests -v
```

### 4.2 独立构建并核验固定包指纹

```sh
cd versions/0.5.5
python3.12 -B - <<'PY'
import json, subprocess, sys
from pathlib import Path

spec = json.loads(Path("BUILD_SPEC.json").read_text(encoding="utf-8"))
out = Path("/tmp/verify-v055-release")
cmd = [
    sys.executable, "-B", "tools/build_file_release.py",
    "--source", ".", "--output", str(out), "--snapshot-id", spec["snapshot_id"],
]
for item in spec["include"]:
    cmd.extend(["--include", item])
built = json.loads(subprocess.check_output(cmd, text=True))
assert built["candidate"] == spec["candidate_fingerprint"], built
assert built["rollback"] == spec["rollback_fingerprint"], built
for mode in ("candidate", "rollback"):
    verified = json.loads(subprocess.check_output(
        [sys.executable, "-B", "tools/build_file_release.py", "--verify", str(out / mode)],
        text=True,
    ))
    assert verified["content_fingerprint"] == built[mode]
print("VERIFIED:", built)
PY
```

### 4.3 变更、验收与发布流程

1. **分支开发**：从最新 `main` 切出独立特性/修复分支，派生新版本目录（如 `versions/0.5.6/`），禁止直接强推 `main`。
2. **自动化与独立复验**：
   - 通过公开 CI（`.github/workflows/ci.yml`：单元测试 + `build_file_release.py` 指纹校验 + 隐私扫描）。
   - 涉及历史读取、授权或切流逻辑变更时，先冻结源码与候选包，交由独立验收方（如 Codex）完成 L4 独立复验（含真实 macOS 后台 `taskpolicy -b` 场景与双 `git archive` 逐字节复构）。
3. **受控部署与回滚**：
   - 上线前先运行 `tools/release_cutover.py preflight` 同时验证新候选包与目标回滚包均可解码现网 `active.json`。
   - 使用 `tools/release_cutover.py deploy --confirm-cutover` 原子替换 `runtime/` 并重启源站，确认存活 PID 与认证门 HTTP `401`。
   - 任何异常时使用 `tools/release_cutover.py rollback --confirm-rollback` 恢复已验回滚包；该流程完整保留 `runtime/work/` 与现行授权/撤权状态。

---

## 5. 归档参考索引

- 历史版本演进与指纹总表：[versions/README.md](versions/README.md)
- 已归档历史分支 Tag：
  - `v0.5.5`：正式稳定发布基线（`b20a5891e3b5047cd6fc261f28223004de84fee0`）
  - `archive/pr5-agent-shared-project-read-20261126`：Draft PR #5 独立认证 Agent 共享文件只读探索原型（`versions/0.4.4-progressive.10`）
  - `archive/codex-unify-project-history-20261126`：`0.4.4-progressive.4` 压缩合并前分支历史
  - `archive/history-stage1-20261030` / `archive/large-200mb-20261030`：早期阶段归档
