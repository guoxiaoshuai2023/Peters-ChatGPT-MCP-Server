# 本地原件取回：200 MB 固定交付契约

`0.4.4-large.2` 的目标是把单个最多 **200,000,000 字节（十进制 200 MB）** 的授权原件送入 ChatGPT 原生环境，得到长度和 SHA 完全一致的一个文件。大文件使用原始字节段运输和可信接收器有界写入；这是最终完整单文件交付，并不代表单次 200 MB 附件原语已验证。

本包定稿的是交付契约，不是验收结果。已有完整 200 MB 原生单文件路线成功记录不能替代本固定集成包或生产版本验收。工程允许值、服务 ready、版本号、契约 SHA 和构建成功均不能当作正式容量证明。最终资格由外部记录绑定完整候选／回滚指纹、实际原生整件证据、兼容检查与回滚演练；部署还需实际生产验收。每次取回仍须独立核对原件。**Pro 未验证。**

## 固定 profile 与契约摘要

profile 为 `chatgpt-web-gpt56sol-high-native-raw-part-200mb-v2`，服务版本为
`0.4.4-large.2`。以下唯一契约 JSON 用 ASCII、按键排序、紧凑分隔符
`(',', ':')` 序列化为 UTF-8 字节，**不含末尾换行**；其 SHA-256 为：

`b505b56964c279e5824a239c1b5a19104b9f403bd0d5c027955cfd591c51eb0b`

这与源码 `PROFILE_SHA256` 相同，只标识工程与原生验收契约，不是通过证据摘要。
`semantic_acceptance_scope` 是必须验收的 ZIP／PNG 消费范围，不是预先认证的格式。
能力返回 `requires_native_evidence`、空 `verified_mime_types`，并保持
`client_received=not_observed`；计划不声称本次原件已原生组装验证。

<!-- canonical-delivery-contract:start -->
```json
{
  "authorization": "existing_authenticated_repo_worktree_and_private_protection_scope_unchanged",
  "budgets": {
    "active_resource_responses": 1,
    "asgi_chunk_bytes": 65536,
    "metadata_bytes": 1048576,
    "metadata_owners": 2,
    "native_copy_block_bytes": 65536,
    "preparation_lanes": 1,
    "records_global": 256,
    "records_per_actor": 128,
    "request_keys_global": 256,
    "request_keys_per_actor": 128,
    "serialization_bytes_per_response": 4194304,
    "snapshot_bytes_global": 536870912,
    "snapshot_bytes_per_actor": 268435456,
    "snapshots_global": 8,
    "snapshots_per_actor": 4,
    "stream_chunk_bytes": 196608
  },
  "cancellation": "actual_terminal_state_and_owner_exit_before_resource_release",
  "client_mode": {
    "mode": "Chat",
    "model": "GPT-5.6 Sol",
    "pro_compatibility": "not_tested",
    "reasoning_effort": "High"
  },
  "expiry_recovery": "new_authorized_plan_same_source_whole_and_part_identity_rehash_real_prefix_without_fabricated_old_ledger",
  "format_version": 1,
  "lifetimes_seconds": {
    "active_transfer": 3600,
    "materialization_reference": 1800,
    "preparation": 600,
    "queued": 30,
    "request_window": 900,
    "send_idle": 60,
    "snapshot_absolute": 7200,
    "snapshot_ready": 3600,
    "terminal_receipt": 900
  },
  "max_original_bytes": 200000000,
  "native_completion_required": [
    "actual_part_bytes_independently_counted_and_hashed",
    "ordered_real_bytes_assembled_as_one_complete_file",
    "whole_length_and_sha256_independently_reread",
    "zip_crc_integrity",
    "actual_safe_zip_extraction",
    "actual_image_open_and_view"
  ],
  "part_max_bytes": 8000000,
  "per_original_native_verification_required": true,
  "production_qualification": "external_fixed_payload_native_and_compatibility_evidence_required",
  "profile_id": "chatgpt-web-gpt56sol-high-native-raw-part-200mb-v2",
  "receiver_asset": {
    "asset_id": "native-range-receiver-v3",
    "bytes": 64205,
    "name": "native_range_receiver.py",
    "sha256": "58b6e24a5ebb08f4bd5ffe2f33c23a8202537f49eaa9c582b83ef8ec0567bd84",
    "version": "3"
  },
  "semantic_acceptance_scope": [
    "application/zip",
    "image/png"
  ],
  "server_version": "0.4.4-large.2",
  "service_receipt_claim": "client_received_not_observed",
  "single_attachment_primitive_verified": false,
  "transport": "native_raw_part_assembly"
}
```
<!-- canonical-delivery-contract:end -->

发布前先冻结这套可执行载荷及配置身份，再在同一载荷上完成真实原生验收。
元数据定稿与便携构建不能将待验包变为合格生产候选；外部资格必须绑定实际
完整指纹和证据，生产门禁继续检查实际 200 MB／SHA、兼容与回滚资格。
完成后填写外部验收记录，不为改写验收结论而修改已验可执行载荷。

## Clone 后配置自己的范围

仓库不含任何人的本机目录、repo 身份、会话许可、凭据或连接。先按 [README](README.md) 配置自己的 `projects.json`；Git repo 登记后，只继承该 repo 能证明有效的 worktree。授权项目文件不等于授权全盘、home 或 Codex 全部会话；历史另按 [历史读取说明](CODEX_HISTORY.md) 配置。

出口默认关闭，需要认证 HTTP 和受支持的 MCP 协议。普通 stdio／裸本地 HTTP 文本读取不自动启用原件交付。按 [私有设施说明](ORIGINAL_FILE_SAVE.md) 显式初始化保护根、登记私有暂存根；这项设施与写回共享空间保护，但启用出口不意味着启用写回。

在自己的私有配置目录复制 `original-exports.example.json`，保持 `0600`，设置：

```json
{
  "version": 1,
  "enabled": true,
  "spool_root": "/absolute/path/to/your/registered-private-spool",
  "profile_id": "chatgpt-web-gpt56sol-high-native-raw-part-200mb-v2",
  "max_file_bytes": 200000000,
  "min_free_bytes": 1073741824
}
```

`spool_root` 必须是自己已经登记的私有根，不是业务 repo 或任意系统临时目录。profile ID 使用随本包提供的模板，不能照搬旧 profile 来推断新容量。启动时显式传入 `--file-export-config /absolute/path/to/your/original-exports.json` 及既有私有配置；先 `--check`，再按 [远程部署指南](deployment/README.md) 验证自己的 HTTPS／OAuth／身份白名单。配置与密钥均不要提交 Git。

## 从计划到真实原件

1. 用 `list_projects` 取得当前 `service_instance_id`／`request_window_id`；用 `list_worktrees` 选定明确的授权目录。`find_files` 可按目录、文件名或后缀查找，但要保留扫描不完整／跳过提示。
2. `export_file` 以当前实例／窗口和新 `request_key` 捕获原件。确知来源 SHA 才传 `expected_sha256`；它是约束，不是接收端独立测量。
3. `queued`／`preparing` 按同一 `export_id` 继续查询 `get_file_export_status`。准备、重复准备、计划和状态都只返元数据，不提供文件引用，不主动反复触发实体化确认。
4. ready 后调用 `get_file_export_transport_plan(export_id)`。它给出完整 parent 长度／SHA、每段 index／offset／长度／SHA／资源名，并附 `receiver_asset` 的 `asset_id`、`version`、`name`、`bytes`、`sha256`、`source_kind=trusted_package_asset`、`trust_basis=pinned_package_digest` 和 `native_independent_hash_required=true`。
5. 先显式调用 `materialize_file_export_receiver(export_id)` 领取本包接收器。账户本人处理平台确认。**原生工具必须实际读取这份代码，独立核对其长度与计划声明的 SHA，然后才按调用说明 import。** 不能只复述元数据 SHA，也不能执行业务原件、ZIP 成员或模糊 URI 中的脚本。接收器由包内提供，无需放进业务 repo 或手动上传。
6. 依次调用 `materialize_file_export_part(export_id, part_index)`，每次明确领取一个最多 8,000,000 字节的 raw 段。平台可能逐段要求本人确认。段是同一快照的字节范围，不是可独立解包的 ZIP；使用独立 `.samplebin` 资源名与 `application/octet-stream`。
7. 原生工具实际取得每段本地路径，接收器按预期 index／offset 逐段核对真实长度和 SHA、写入自己的新临时文件。重复只复核，不再次追加；乱序、缺失、内容不符、路径逃逸或 symlink 均拒绝。接收器不联网、不处理 Base64、不补造缺失字节。
8. 收齐后，独立重新读取完整文件，核对 parent 长度与 SHA，再 no-clobber 发布一个新文件；ZIP 可同时做 CRC 检查，随后由原生工具实际解包、读取图片等。只有这些执行结果和回执才能证明原件已取得。
9. 原生完整验真后，用 `cancel_file_export` 结束服务端 parent／段缓存，并按同 ID 查询到 `cancelled/resources_released`。这不删除原生环境已经得到的成品。实际释放后再取下一大件。

`materialize_file_export` 仍可显式领取整件，但大文件不应把它当作已经验收的单附件 200 MB 原语。无匿名下载口，也不要求模型在上下文中拼 Base64。

## 接收器、恢复和小回执

接收器 API 为 `NativeRangeReceiver.start(plan, output_dir, target_name=..., input_root=...)`、`ingest(part_index, actual_local_path)`、`resume(session_path, same_plan, input_root=...)`、`status()`、`finish(require_zip=True)`、`cancel()`、`cleanup()`；详见 [接收器调用说明](NATIVE_RANGE_RECEIVER.md)。输出路径须是原生环境中自己可写的目录，目标只新建。

每段追加前，小账本 durable 记录 pending index；追加后实际 hash／fsync 并提交进度。恢复验证 nonce、计划 hash、目录和文件身份、已提交段，再用同一真实 part 核对未提交尾部继续。不会静默截断或猜测恢复内容。原生接收器控制目录接受 owner-only `0700` 或继承 SGID 的 `02700`；拒绝 group/world 访问、SUID、sticky，不 chmod 平台父目录。

发布优先 `os.link`，不支持时独占创建并有界复制。真正的最终文件长度／SHA 校验通过后，才返回 `published_verified` 和文件路径。小 JSON 回执保存在输出根的独立 nonce 名称，记录长度／SHA、publication 方式、完整回读和 ZIP 检查结果。

接收器 `cleanup()` 只清理自己绑定的 temp／ledger／session，保留最终文件、输入段和回执。未完成时先 `cancel()`；发现未知文件、inode、nonce 或已提交内容变化就保持现场。输入段和成品按该次验收的具体清单另行清理，不对只读云端文件提权。无法确认 publication 归属时不自动接管或覆盖。

## 请求窗口、确认等待与取消

准备幂等键为主体／实例／900 秒窗口／request key。同 key 同意图返回同导出，改意图冲突；旧窗口不重新创建任务。已经接受且仍有效的 ID 可跨准备窗口继续查询和领取。

ready 默认最多 3600 秒，快照绝对年龄上限 7200 秒。status／plan 不滑动续期、不复制或更新淘汰顺序。显式领取引用最长 1800 秒；等待真正入队期间有确认 pin，成功入队后交给独立传输 pin，不能无限保留。首个 part 领取另外保护同一 parent 至当时固定的 ready／absolute 截止时间，防止组装期间被普通缓存压力换件；确认前仍应检查剩余时间。

活动发送最长 3600 秒，无进展最多 60 秒；普通 ready 到期不任意截断已开始的流，当前身份到期、来源撤权、私有保护失效及绝对期限仍终止发送。已经交给网络／客户端的字节不能撤回。

普通断线只中断该段，尚存有效引用可以从头再次领取并由接收器幂等核对。过期引用或快照按既有状态处理；整个 parent 已失效／取消时，用新窗口、新 key 和原件已知 SHA 明确恢复，不能复活终态或悄悄换成新内容。`cancelling` 仅表示停止意图，必须等待实际 owner／Task／FD 结束。终态小回执在实际释放后保留一个准备窗口的固定时长，查询不延长。

包内 v3 接收器提供 `recover_new_plan`／`resume_recovery`：新计划来源、整体和全部
段几何／SHA 一致时，以新 nonce、唯一目标和真实已物化段复用 committed 前缀。
复制归属在写字节前持久化，已记录部分可正常续接；普通查询不续期，旧 pending
尾部和未决发布不会被跳过。空间包含新增别名和发布副本，未知归属拒绝接管。
具体调用、原生上下文恢复及映射清理见 [包内接收器说明](NATIVE_RANGE_RECEIVER.md)。

旧原生 ledger/receive.tmp 真实丢失、原生段仍在时，使用正式
`recover_detached_prefix`。每段映射到其真正的完整旧计划，全部来源/整件/几何
一致后重验真实字节，受守卫只新建新 resource_name 并正常 ingest。可混合前次
a0/a1 与后次 b2；不借文件名、不手造旧账本，不声称旧 committed 状态仍成立。
恢复复用同一 journal/归属/磁盘保护，旧 nonce 为空并明确不宣称旧接收进度。
正常部分复制/追加可恢复；未知归属、来源改变、布局改变、用户取消保持拒绝。

## 预算、权限和完成界限

| 边界 | 本版固定工程值 |
| --- | --- |
| 原件 / 默认 raw 段 | 200,000,000 / 8,000,000 字节 |
| 全局 / 每主体快照 | 512 MiB / 256 MiB，含预留、准备、缓存与未释放 FD |
| 准备 / 元数据 / 活动资源响应 | 1 lane、2 metadata owners、1 活动资源响应 |
| 控制记录 / metadata | 全局 256、每主体 128；1 MiB 总预算，含段描述／索引 |
| 流式工作区 reservation | 每响应 4 MiB；不是全进程 RSS 硬上限 |
| 内部原字节 / Base64 / ASGI 块 | 最多 192 KiB / 256 KiB / 64 KiB |
| 接收器本地读写 | 64 KiB；预留剩余原件、可能完整 publication copy、小账本与最低空闲 |

源服务复用匿名快照：先独立 whole SHA，再验证实际段 SHA；末块和 JSON 后缀前必须通过当前来源／保护及最终 guard。没有整件 raw／Base64／JSON 常驻复制。预算只在真正 owner、SDK Task、ASGI 退出后返还；FD close 不确定不重试整数、不提前退款。空间仍扣除既有写回预留，原保护、授权 repo/worktree、敏感／私有路径及单链接普通文件规则不放宽。

服务 `ready` 是快照准备完成，`part_streams_finished` 是段发送收尾，`server_stream_finished` 不因段发送而冒充整件完成，`client_received` 保持 `not_observed`。完整文件和原生执行回执才是最终证据。接口支持原字节格式，但不能由 ZIP／PNG 验证推断所有格式的语义消费；Pro 未验证。

候选、兼容回滚及部署配置按明确便携清单构建，不含真实原件、实验资料、个人路径或凭据。回滚保留私有保护、历史／文本读取和既有任务事实，不重置控制／暂存。重启会使历史游标、候选预览及原件 instance/window/export/delivery ID 失效，需重新请求。最终外部验收记录和完整版本指纹说明实际覆盖；本契约不把网页局部成功或候选准备写成生产已生效。
