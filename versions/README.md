# 独立发布源码快照

**当前正式稳定维护基线：[`v0.5.5`](0.5.5/AGENT_HISTORY.md)**（正式 Tag `v0.5.5`，冻结源码提交 `b20a5891e3b5047cd6fc261f28223004de84fee0`；维护入口见 [MAINTAINING.md](../MAINTAINING.md)）

[`0.5.5`](0.5.5/AGENT_HISTORY.md) 从 [`0.5.4`](0.5.4/AGENT_HISTORY.md) 派生，定向闭合 macOS `ProcessType=Background`（`taskpolicy -b`）后台调度下大型 Antigravity Desktop 轨迹冷启动步骤超时，以及统一 `v2` 工作进程超时状态报告与撤权保护：

- **Antigravity 协作式有界步骤让出（后台 QoS 冷启动稳定收敛）**：将 `Adapter._snapshot`、`_recover`、`capture`、`_steps`、`_generations`、关联子 Agent `verify_senders` 与公开消息脱敏 `_record` 拆分为协作式生成器让出点（`capture_iter`、`snapshot_iter`、`snapshot_for_inheritance_iter`、`_record_iter`），完整保留全部 TOCTOU 复采样、SQLite WAL/SHM 一致性校验与 `_CAPTURE_CACHE` 四组物理戳绑定；在正式后台 QoS 下冷启动查找、等待续页、全量分页读取与 `view="latest_turn"` 均在单步监管预算内稳定完成。
- **统一 `v2` 工作进程超时诚实报告与撤权即时阻断**：在 `IsolatedHistory._call` 中区分无数据控制应答（`control_only`：`processing_timeout`、`resource_exhausted`、`restart_required`、`snapshot_expired`），真实步骤超时如实返回结构化 `processing_timeout` / `restart_required`（聚合检索仅将该来源标记为 `warnings=["processing_timeout"]` 并正常返回健康来源命中），不再误报物理拓扑校验异常；同时在入口与控制应答路径复核实时 `v2` 项目、来源及 `denied_threads` 权限，读取途中或超时后撤权立即停止交付。
- **正式验收与发布状态**：本快照在 macOS arm64 / Python 3.12.14 上完成全部回归测试、独立技术复验（L4 PASS）、两次干净 `git archive` 逐字节复构校验、受控生产切换与真实 ChatGPT 外部端复验（L5 PASS），正式转为当前唯一稳定维护基线；`versions/0.5.5/` 源码保持冻结不变以确保下方构建指纹恒定。实际主机私有配置与验收证据保留在操作者本机私有目录，未收入公开仓库历史。[构建清单](0.5.5/BUILD_SPEC.json)

| `v0.5.5` 正式固定包 | SHA-256 |
| --- | --- |
| source content | `4e3c3373183594de9599035c128198a96d6899b252bef060f9d534e1b39e56c3` |
| candidate（正式生产运行包） | `66d641052da882a1aa96f4b4dcbf476322336298416e0cbbd0cfc35d60f9ca9b` |
| generated inspection rollback | `b20c3b5ff288d795f042a3ccab02839afe89a3182386ceefec0a25f56b17e739` |

[`0.5.4`](0.5.4/AGENT_HISTORY.md) 从冻结的 `0.4.4-progressive.12` 派生，面向产品化修复四来源（Codex、Antigravity Desktop 2.32.1 / 2.33+、Codeg、DeepSeek Harness）的历史发现、归属核验、完整性恢复、官方公开视图对齐与双向搜索归属：

- **项目物理身份、墓碑与 Codex 分叉/附属/子 Agent 精确归属**：废除 macOS APFS 父目录 `st_ctime_ns` 误拒机制（仅当 `st_ctime_ns > st_mtime_ns` 视为路径拓扑变更），新增独立持久化路径墓碑 `.path-tombstones.json`（`0600`，`active.json` 保持与 `.12` 回滚兼容）。普通稀疏 `paginated` 分叉按原生 `history_base` 重建截断点前的已授权同项目父前文（排除分叉后父追加，缺截断证据显式报 `inherited_prefix_unverified`）；附属会话（`attached_thread=true` 或 `attached_thread_parent_id`）与原生派生子 Agent 会话（`source` 声明 `subagent`）继续强制完整父血缘授权、同项目隔离与翻页中途撤权校验（`parent_context_inlined=false`），默认全文与检索仅交付该子会话自身的已核验公开消息；无条件过滤 `auto-compact-*` 内部压缩桥接记录与非 `"user"` 来源（`provenance.type != "user"` 或 `multi_agent.*` `content_item_kinds`，如 `wait_agent` 工具产生的多 Agent 完成通知）注入块以消除父子会话双向误命中，同时不在四来源公共 `sanitize()` 中按纯文本标签剥离 `<subagent_notification>`，原样保留用户或助手在公开会话中输入的字面 `<subagent_notification>` 文本、标题与后续段落；剥离图文附件外层合成 `<image ...>...</image>` 包装以对齐官方镜像去重，同时保留真实连续重复发送与字面 `<image>` 文本；统一与兼容入口 `view="latest_turn"` 对齐可靠 `latest_turn_id`。
- **Antigravity 双轨验证、提交边界保护与全依赖物理戳缓存**：支持 Checkpoint 压缩步骤双轨恢复（`compacted_steps_from_transcript`）、子 Agent 同源隔离校验、活跃进行中线程（`thread_in_progress`）、稳定 `turn_id` 及通用内建工具提交边界保护；`_CAPTURE_CACHE` 端到端绑定 `INDEX`（+WAL/SHM）、主轨迹 DB（+WAL/SHM）、两份 transcript 及全部关联子 Agent DB（+WAL/SHM）四组物理戳，闭合验证后入缓存前的并发窗口。
- **四来源诚实覆盖、并发性能与损坏清单标准回滚**：Codeg 诚实报告 `unsupported_agent_types`，统一输出零泄露 `unverified_project_candidates` 计数并提供 `agent_history_admin lint` / `preview-coverage`；工作进程池调整为 4 槽，配合纯物理戳绑定、无授权态的 Codex 证明/投影/前缀缓存及批处理范围复核满足温态查询延迟目标；`tools/release_cutover.py` 对载荷与最终 `manifest.json` 采用同目录临时文件 + `fsync` + `os.replace` 原子提交，支持从 0 字节、半截截断、非法 UTF-8 或缺清单现场执行标准 `rollback --confirm-rollback` 恢复 `.12` 并保持已撤权状态生效，重启探针严格要求存活 PID 与认证门 HTTP `401`。
- 本快照在 macOS arm64 / Python 3.12.14 上完成完整单元与安全回归套件全部通过（含分片导出到期测试对并发文件描述符整数复用的原快照 inode 关闭校验，以及四来源字面 `<subagent_notification>` 公开正文保留回归），两次独立干净 `git archive` 重建逐字节一致；实际主机私有验收证据保留在操作者本机隔离目录，未收入公开仓库历史。当前仍处于隔离冻结状态，待独立技术复验及真实外部连接验收后决定生产切换。[候选构建清单](0.5.4/BUILD_SPEC.json)

| `0.5.4` 固定包 | SHA-256 |
| --- | --- |
| source content | `c07578965eab82bd5ff69ca34e33a246c6bb2cab9f58f39dd0c4e28e9d59cbc0` |
| candidate | `71cdd6e3cd14630f20ab5a8bcb044f9e82c276153945bcbe9fb8e240f86e9b83` |
| generated inspection rollback | `4561333f752627a61447e8a67971580e622773d816039afb6d7936f4b3340054` |

[`0.4.4-progressive.11`](0.4.4-progressive.11/AGENT_HISTORY.md) 从冻结的 .9 派生。同一 ChatGPT 连接使用一份项目白名单获得已启用的文件能力和经核实的多来源会话。隔离源站已读回六个项目中四种真实来源的会话，包括 Antigravity Desktop 2.33.0 自动归属的记录。正式启用仍需通过真实 ChatGPT 连接的查读与原生文件交付验收。[候选构建清单](0.4.4-progressive.11/BUILD_SPEC.json)

统一项目白名单的隔离候选为 [`0.4.4-progressive.9`](0.4.4-progressive.9/AGENT_HISTORY.md)。它预览迁移，统一各已启用来源的项目授权，并将旧 Codex 工具纳入同一授权检查。Antigravity 自动归属仍待验收。构建清单和固定包指纹见 [BUILD_SPEC](0.4.4-progressive.9/BUILD_SPEC.json)。

Antigravity 版本兼容修复快照为 [`0.4.4-progressive.8`](0.4.4-progressive.8/AGENT_HISTORY.md)。Antigravity 来源可以省略 `format`，读取器校验 v3 会话索引、原生日志结构与消息来源，按现有账号、项目和逐线程授权读取。显式配置 `2.32.1` 和 `2.33.0` 仍可用。按[构建清单](0.4.4-progressive.8/BUILD_SPEC.json)可复构以下发布包。

| progressive.8 固定包 | SHA-256 |
| --- | --- |
| candidate | `e452737fd9788ce605bab542837b5aa9df410d58698e2aa75c9ee182ccf170c2` |
| inspection rollback | `7782089432dc782717c58b53477d954344aaa8d6fe2a69fe6d5b4c6e9df99962` |

Antigravity 步骤缺口修复快照为 [`0.4.4-progressive.7`](0.4.4-progressive.7/AGENT_HISTORY.md)。完整日志与精简日志的现存步骤逐条对应且缺口相同，仍恢复已验证的公开正文并标记覆盖不完整。构建清单见 [BUILD_SPEC](0.4.4-progressive.7/BUILD_SPEC.json)。

Antigravity 完整回复修复快照为 [`0.4.4-progressive.6`](0.4.4-progressive.6/AGENT_HISTORY.md)。它在核对同线程精简日志与完整日志后恢复截断的可见正文，继续使用逐线程授权和既有过滤。构建清单见 [BUILD_SPEC](0.4.4-progressive.6/BUILD_SPEC.json)。

多 Agent 历史候选版 [`0.4.4-progressive.5`](0.4.4-progressive.5/AGENT_HISTORY.md) 以冻结 `.4` 为基线。它增加 Codeg、DeepSeek Harness 和 Antigravity 的只读会话工具及单独授权配置。候选构建清单见 [BUILD_SPEC](0.4.4-progressive.5/BUILD_SPEC.json)。真实应用历史与 ChatGPT 连接器的对照验收尚待执行。

最新项目会话修复快照为 [`0.4.4-progressive.4`](0.4.4-progressive.4/README.md)，由冻结 `.3` 派生。`inherit_projects=true` 覆盖所有已配置目录项目及身份校验通过的仓库项目，现有／未来线程无需单独授权；目录项目覆盖真实子树，仓库项目覆盖有效登记 worktree。每条线程的索引 cwd、全部记录 cwd 和 fork 身份仍须通过验证，撤权及目录身份变化使旧游标失效。默认配置不开放历史，迁移时逐一核对项目范围并移除已由项目继承覆盖的冗余显式线程例外。

`public-jsonl-stream-v4` 支持分块读取 `.jsonl.zst`，兼容索引仍指向未压缩旧路径；12–64 MiB 记录完整校验 JSON 并只保留归属／轮次字段。缺失、损坏和资源限制明确报错或标记覆盖不足。已公开异步消息保留原位，注入的 harness／AGENTS 用户块继续过滤。工具证据独立授权，搜索 `limit` 在 MCP schema 中限制为 1–20。

本快照在 macOS arm64 / Python 3.12.14 上完成 **811 项完整回归测试，全部通过**。按本版 BUILD_SPEC 构建的 candidate 与 inspection rollback 均通过逐文件校验，各含 48 个载荷文件。完整套件包含项目继承、撤权、压缩历史、公开消息、文件保存、分片导出及持久身份回归；没有以本次测试冒充新的原生附件收件或容量验收。

修复来源此前在一台 macOS arm64 部署通过 **221 项定向测试**及真实认证 MCP 验收：5 个已授权项目、77 条可发现线程，含 43 条压缩来源；关键线程分页和公开原文对照、越权及游标边界通过。本冻结版的运行 Python 代码与该已验证来源逐文件相同，另行冻结发布文档及快照标识。各主机实际部署以本机 manifest 和验收记录为准；另一台尚未开机的主机仍待部署验收。真实路径、线程 ID、凭据和原文未收入仓库。

| progressive.4 固定包 | SHA-256 |
| --- | --- |
| candidate | `5e2dd661382d9fb95ff7aecc86c115f5ab4d92bee7bb4bd6c7e0fc757faf805f` |
| generated inspection rollback | `de9e3f65b47c8ee36fe1576471a9bd454735d5c5e8a2f1cf903b59a2d9e4b6b4` |

本版按自身 `BUILD_SPEC.json` 构建。旧快照及文件保存、分片导出、receiver/loader 的源码保持冻结；本次同步不启用原件写入／导出，不迁移持久任务或复用其他机器的私有配置。Python 3.12 环境新增锁定的 `backports.zstd==1.8.0`，Python 3.14 及以上使用标准库。

以下保留 `.3` 的历史验收。该快照从冻结 `.2` 修复分片父任务的到期计时：原单调期限和固定 Unix 截止任一达到即进入不可复活的过期状态，覆盖准备、查询、同键重试、领取、资源读取、发送及后台回收。唤醒后不会仅因单调时钟未计睡眠而继续保留已过截止的父任务。资源仍沿原所有权流程关闭；实际准备/响应所有者、SDK/ASGI、pin 和 FD 未退出时继续保留占位。legacy 的计时/grace、不可变计划、接收器/加载器、权限和容量配置保持。

本轮先在未修代码上确认核心回归失败，再完成 **11 项新增＋59 项继承，共 70 项不同的定向检查**和独立代码审阅。独立墙钟/单调时钟配合真实临时文件、FD 及在途 owner 验证睡眠失配、各入口、整数截止、回拨及实际释放；没有重复真机睡眠或重跑全部历史测试。新包完成一次认证 SDK 的 **100,000,000 字节、13 段**真实传输、SHA/CRC、重复段/恢复、释放、legacy、重启及已有 inspection 回退演练，沿用获批的额外 RSS 256 MiB 目标；本轮定时采样额外 RSS 约190 MiB，累计高水位相对当前基线的保守差约200 MiB，两者均低于该门。

正式 origin 已切换并以真实认证 MCP 响应、审计及进程身份完成健康签收；私有配置、仓库 PIN、锚点、旧行事实、schema 和账本连续。

上线后原生小门首轮 **Pro / Work 调用面**未取得 helper，已取消并确认真实释放；保留失败后，有界复验 **Chrome / High / 原生 Python**实际接收 helper 和唯一数据段，固定 loader pin、根绑定、独立调用 A 的8192字节/SHA测量先于 B 接收、发布后整件 SHA、ZIP CRC/安全解包、8×8 RGBA PNG 实际显示和源端释放通过，随后恢复原 Pro 档位。完整报告的部分 MCP 响应是公开返回的转录，实际 Python 代码/输出、源审计和独立释放核验另行保全，不冒充逐字原始回执。本机未确认取得完整原生 JSON 下载；本机保存的公开执行投影有长源代码行截断限制。平台选择不同调用路径的原因仍未定位；本修复不宣称解决普通原生附件未收件的问题。

本轮只新增8 KiB原生回归，不将其称为新的100 MB原生大件验收；100 MB原生历史资格见下文 `.2`。新 `.3` 按自身 BUILD_SPEC 的45项白名单重构，helper/loader 原字节不改。`.2` 及其他旧快照保持原字节；正式维护计划绑定新 candidate 和已有 `.2` inspection fallback，新构建出的 `.3` rollback 指纹仅为可复构产物，不混称本次实际 fallback。

| progressive.3 固定包/资产 | SHA-256 |
| --- | --- |
| candidate | `3b61805a3557e646281d8a897f1b24c96cdf1de0e9a9a2bccacf4222ad59fce6` |
| generated inspection rollback | `9efffcf916eb8a8488862be4cb28da729733a9e7228d1cd99249b6e367ea5277` |
| 本次绑定的既有 inspection fallback | `9386edb6d13ceefd33f644c3ac0c2c3c555dd9aeee71fe0f132139c8d333c852` |
| helper / 57,452 bytes | `fbe30b9e3ed604e246f9fa559524780ea7c03eec254fcae6e34faecc1d1662f7` |
| 唯一 loader / 10,050 bytes | `5a539432ae8796ee880ae8a3c128e18718991233a239e8133eec7b55091150cc` |

此前 [`0.4.4-progressive.2`](0.4.4-progressive.2/README.md) 在 [`0.4.4-progressive.1`](0.4.4-progressive.1/README.md) 的 `raw-parts-v1` 基础上，将宿主交付的只读 helper/分片与当前用户的私有可写状态分开校验，并用唯一固定加载器在校验、关闭输入后执行同一源码缓冲。`.1` 保留为历史协议与旧附件归属检查的复现对照，不是推荐部署版本；`.2` 的快照内文和 BUILD_SPEC 保持冻结原字节。以下为既有验收事实。

**2026-10-31 的 100 MB 容量验收**复用同一 `.2` candidate、helper、loader 和 `raw-parts-v1`，只通过新建私有配置及受审运行计划将容量调整到 **100,000,000 字节**，分为 12×8,000,000＋4,000,000 字节共13段。在上述 ChatGPT Web profile 中，13段均实际原生收件；每段先独立测量、持久化和公开，再在后一次调用接收，重复段追加0、新对象恢复、最终整件 SHA、ZIP CRC、安全解包及8×8 RGBA PNG实际显示通过。源端14个资源槽（helper＋13段）各完成一次实际读取，取消后实际快照关闭；旧任务、账本、schema、仓库PIN及身份保持。核心冻结快照内文不回填，当前容量状态由本索引记录。

本次只补 **13项定向检查和23项既有工具回归**，没有重跑763项全套或逐档重测30/50/70 MB。认证SDK的100 MB新资格按获批的额外RSS上限 **256 MiB** 通过，实测额外峰值约180.7 MiB；此前两个128 MiB失败及一次无效采样保留，没有改写为通过。原生期间30秒离散观察到的额外RSS最高约73.2 MiB，不据此声称捕获所有瞬时峰值。该资源目标是验收阈值，并非OS强制内存限制，也不宣称已解决原内存现象。核验窗口内另有两条无法归属的历史读取权限拒绝和3条并发上限WARNING，调用者与因果未确定；本轮14个文件资源槽的匹配完成记录均成功，不承诺全局零错误。

根目录 [`rehearse_progressive_release.py`](../tools/rehearse_progressive_release.py) 新增 `--tier-bytes`，默认仍为30,000,000；`--rss-profile capacity100-256m` 仅允许精确100,000,000及 `--allocator-profile system-default`。后者只对子进程环境副本移除 `MallocNanoZone`，应与实际目标运行环境一致，默认仍继承环境并使用128 MiB门。新 [`render_capacity_acceptance.py`](../tools/render_capacity_acceptance.py) 校验独立源哈希与分片几何，复用固定loader和一次公开的A/B控制源码；生成提示本身不构成原生收件证明。

此前30 MB基线的 `.2` 完整套件 **763 项通过**，并完成真实 Linux UID0→非 root UID 的隔离接收、认证 SDK/重启/inspection 回退演练。在一个独立配置的 **ChatGPT Web / GPT-5.6 Sol / Chat / High** 环境中，实际接收并重组 30,000,000 字节合成 ZIP，四段为 8,000,000 / 8,000,000 / 8,000,000 / 6,000,000 字节；独立验证各段和整件 SHA、重复段追加0、新对象恢复、ZIP CRC、安全解包及 PNG 实际显示。每段先单独完成测量、持久化和公开，再由另一次调用接收；不使用只在接收后汇总打印的早期运行作为严格验收证明。

随后完成一次受控 origin 服务冷启、新认证健康、旧读取回归及全新小件原生验收，旧任务事实、schema、账本和身份配置保持。三阶段实际 metrics 在健康签收后 22.545 / 356.053 / 727.515 秒采集，首末跨 704.970 秒；不是 exact 0/5/10 分钟。小件源端在中间采样点后约24秒关闭，末点前已确认释放。正式三阶段未见新增审计或服务日志错误；额外尾查的未归属拒绝和一次重试后恢复的工具错误及其原错误体保全缺口仍保留，不据此承诺长期或全局零错误。

上述结果分别签收同一已验 profile 的30 MB基线和新增 **100 MB 原件导出**。旧单次出口仍为12,659,780字节；50/70 MB未单独做原生验收，其他host/client/profile及实际整机重启不由这些结果证明。新通道默认关闭，原模板容量仍为30 MB；启用100 MB须create-only新私有配置并重新绑定运行计划，不能原地改写已绑定配置。视频/PSD等作为不透明字节传输，不据ZIP样本声明其内容解析能力。合成样本可用快照中的 [`generate_progressive_fixture.py`](0.4.4-progressive.2/tools/generate_progressive_fixture.py) 重建；实际样本、原始回执、机器目录、身份、账号授权和审计留在操作者私有环境。

| progressive.2 固定包/资产 | SHA-256 |
| --- | --- |
| candidate | `9875f50d20aef72e39cf90c10c28d82fa433d9cddcdfcfaaa1f0efa4e303b9db` |
| inspection rollback | `9386edb6d13ceefd33f644c3ac0c2c3c555dd9aeee71fe0f132139c8d333c852` |
| helper / 57,452 bytes | `fbe30b9e3ed604e246f9fa559524780ea7c03eec254fcae6e34faecc1d1662f7` |
| 唯一 loader / 10,050 bytes | `5a539432ae8796ee880ae8a3c128e18718991233a239e8133eec7b55091150cc` |

以下保留兼容基线。`0.4.3-context.4` 在 macOS 上完成 563 项测试，增加受限的已完成任务历史回执匹配：同一调用者/请求键、相同目标与已绑定哈希和长度，且完成、发布、持久性、验证、写者退出、epoch及目标权限均通过时，可返回明确嵌套的原任务回执；不重新接收、验证或批准第二个来源引用，不创建任务或改写旧事实。

[`0.4.3-context.3`](0.4.3-context.3/README.md)是该兼容变更的基线，540 项测试通过。私有保护和仓库 pin 使用卷 UUID、文件 ID 与整数创建时间作长期身份，保留运行时设备号和 inode 检查；历史记录严格解析上限为 12 MiB，worker 的 256 MiB 与缓存的 128 MiB 限制保持。现有任务保留原事实，不自动重绑失败授权。

[`0.4.3-context.2`](0.4.3-context.2/README.md)是上述身份修复的基线，532 项测试通过；`.3`仅增加历史记录大小兼容及对应测试。两版均包含 plan/SHA 绑定的显式本地迁移和 origin 切换工具，需按本机已批准计划执行，不能以构建或 clone 代替身份采纳、运行状态、原生文件消费及实际整机重启验收。当前验证平台为 macOS，未据此声明其他平台通过。

| 修复包 | 完整内容指纹 SHA-256 |
| --- | --- |
| context.4 candidate | `8cc577bca45113bc3eaf5bd3010fa32981f6013a4e1684e8c30808449c248340` |
| context.4 compatible rollback | `cd4dd058e7f101ab452358046fa90c66dd4ce07223742620298bb31fcec86727` |
| context.3 candidate | `7d0c35081e2065ef66ee02fb30d87f64055e75ec5a46da63a433ce3bae141b15` |
| context.3 compatible rollback | `c4e88a7940e40b50ba3fcd11aebbda14e376aeab219f2a9a48dfc3013fb7087a` |
| context.2 candidate | `cb6b1d6f18b045559ec63b2f71587686610c8d957de635332774eb9d8c6cc3a5` |
| context.2 compatible rollback | `1f4ad161d41d319ac12f7e79335a799db885a7db124d921d7b3011935e83d28a` |

每版使用各自 BUILD_SPEC.json 的明确白名单构建并核对指纹。以下保留 `0.4.3-context.1` 原件读取基线的说明及验收范围，不能把其历史客户端结果自动算作新版本验收。

`0.4.3-context.1/` 在固定的 `0.4.2-files.1` 上增加默认关闭的原件读取。新增 `find_files`、`export_file`、`get_file_export_status`，沿用明确授权的 repo/worktree、敏感保护和既有16工具。归档不等于自动部署；clone 不继承本机目录、仓库身份、账号、会话授权或云端连接。

仅实现认证 MCP ResourceLink / resources/read 这一条交付路线。实测 ChatGPT Web / GPT-5.6 Sol / Chat / High：小 ZIP、12,659,780 字节 ZIP 的实际接收、原生哈希、解包和看图通过；未知扩展名合成样本也通过。Pro、视频和交互浏览没有据此获得已验证结论。原件上限12,659,780字节，默认一次完整资源响应；详细配置与失效恢复见 [原件读取说明](0.4.3-context.1/ORIGINAL_FILE_EXPORT.md)。

源码83文件包含原25个测试文件及11个新增回归文件，共448项合成测试通过。测试只在临时合成目录中运行，仓库不保存验收原件、真实配置、凭据、个人目录或原始对话。源码 development marker 用于本地测试；构建器另生成 candidate / rollback marker，不要直接运行归档目录来代替发行包。

## 本地验证

需要 Python 3.12 和按快照 requirements.lock 准备的隔离环境；当前验收平台是 macOS arm64。

```sh
cd versions/0.4.4-progressive.4
python -B -m unittest discover -s tests -v
```

## 复现固定包

在快照目录使用尚不存在的输出路径。构建不运行服务，也不修改机器授权：

```sh
python -B - /absolute/path/to/new-release-pair <<'PY_BUILD'
import json
from pathlib import Path
import subprocess
import sys
spec = json.loads(Path('BUILD_SPEC.json').read_text())
command = [sys.executable, '-B', 'tools/build_file_release.py',
           '--source', '.', '--output', sys.argv[1],
           '--snapshot-id', spec['snapshot_id']]
for path in spec['include']:
    command.extend(['--include', path])
subprocess.run(command, check=True)
PY_BUILD
```

| 包 | 完整内容指纹 SHA-256 |
| --- | --- |
| candidate | `4ffb382ef797dbe6bbe1cb1eab3f8e5ce5cf12e6166d256aeb41ecb8dd1849a9` |
| compatible rollback | `d6bfb55d2fbaa53fc25da83406fa29ee9b30961b7be41651ec4102398ed9fafc` |

执行 `python -B tools/build_file_release.py --verify /absolute/path/to/package` 并独立比较完整指纹。两包只包含38个明确选择文件，加生成的 marker / launcher；manifest 与上述摘要不是数字签名。

## 部署与回滚边界

使用全新、经过核对的运行副本，保留不可变归档包。配置留在私有位置，现有 Cloudflare 入口的审计写在运行副本 `work/`，运行产物与载荷指纹分开核对。不得用 `deployment/manage_services.py install/stop` 进行 origin-only 切换，它会同时操作源和隧道。

原件出口独立显式配置，复用已初始化的私有保护及暂存根；不迁移保存数据库，不自动开启写回，不扩大项目或历史范围。发布前确认旧源和相关子进程真实退出，再启动候选并刷新原连接定义。未确认退出时隔离，不盲目接管。

本兼容回滚包关闭新原件出口和新文件写入，保留私有保护、历史/文本读取及已有任务和发布事实的只读检查。实际执行回滚须遵循当次明确授权，不由归档或构建自动触发。

## 历史快照

`0.4.2-files.1/` 保留原字节，含原件后台保存与兼容检查回滚，其 candidate 指纹为 `5a9ee7e1ed2c1c811384b79e374133b52a6e33e64db80f59d6cb212bfa835982`、rollback 为 `2af308177c4b85c8df6a2e8290624575fa962cd9fbede740ff8c50ccd6faddc4`。历史事实不用于推定当前机器已运行该版本。
