# 可信接收器：把实际原生段写成一个原件

这是本包提供的静态 helper，不是业务 repo 中的代码。先调用 `get_file_export_transport_plan` 取得 `receiver_asset`，再调用 `materialize_file_export_receiver` 明确领取；按当前授权处理平台确认；平台要求只能由本人操作时由本人完成。无需把 helper 放入业务 repo，也无需手动上传。

## 先在原生环境核验代码

代码资产的 `name`、实际长度和 SHA 以当前包的计划 metadata 为准。`0.4.4-large.2` 固定资产为 `native-range-receiver-v3`／`native_range_receiver.py`，64,205 字节，SHA-256：

`58b6e24a5ebb08f4bd5ffe2f33c23a8202537f49eaa9c582b83ef8ec0567bd84`

下载卡片或复述计划不算校验。让原生工具实际读取已收到的代码文件，核对长度／SHA 后再 import。不要把原件、ZIP 成员或其他来源同名脚本替换进去；不得执行未核验的文件。

```python
from pathlib import Path
import hashlib
import importlib.util

# helper_path 必须是宿主实际物化的文件路径。
code = Path(helper_path).read_bytes()
asset = plan["receiver_asset"]
assert len(code) == asset["bytes"]
assert hashlib.sha256(code).hexdigest() == asset["sha256"]

spec = importlib.util.spec_from_file_location("verified_native_range_receiver", helper_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
NativeRangeReceiver = module.NativeRangeReceiver
```

原件段本身不执行。接收器只读取已物化的本地文件，不联网、不接收 Base64、不造缺失字节。

## 领取、接收和恢复

`plan` 是 transport plan 的纯 metadata；不要把 part 的长度／SHA 当成 parent 的长度／SHA。每个实际文件名应对应该段 `resource_name`。

```python
r = NativeRangeReceiver.start(
    plan, "/mnt/data", input_root="/mnt/data",
    target_name="received-original.zip",
)
session_path = r.session_path  # 保存精确 nonce 路径，用于后续原生工具调用

# part_path 来自当前宿主真实收到的第 0 段，不能猜测／预造。
r.ingest(0, part_path)
print(r.status())
```

下一段实际到达后再顺序 `ingest(1, ...)`、`ingest(2, ...)`。每次核对本地文件长度与 SHA 后，仅按计划 offset 写入自己的临时文件。重复同段重新验证，`appended_bytes=0`；错序、缺失、hash 不符、路径逃逸或 symlink 会拒绝。

原生工具执行上下文中断后：

```python
r = NativeRangeReceiver.resume(session_path, plan, input_root="/mnt/data")
print(r.status())
# 若 pending_part_index 未提交，再传同段实际文件；校验已有尾部后继续。
r.ingest(next_index, actual_part_path)
```

账本绑定 nonce、plan hash、目标和目录／文件身份。追加前 durable 记录 pending，完成后实际 hash／fsync 提交；已提交和未提交尾部都不能凭口述跳过验证。合法 SGID 平台目录下的 owner-only `02700` session 可恢复；helper 不 chmod 平台目录。

### 源计划过期、源进程重启与原生上下文中断

源 ID／窗口失效时，以新 request key、原件已知整体 SHA 和当前有效 instance／window
从已授权 MCP 重新准备。先确认旧读取真正退出及实际资源释放，保持原期限、限额
和授权。新计划的 project／worktree／相对路径、整体长度／SHA、全部 index／offset／
长度／part SHA 必须一致；旧源 ID、引用和计划不复活。

仍保留旧 session 和实际物化段时，用本包 API 新建 nonce 和唯一目标，复用真实
committed 前缀。可信调用者传真实完整的新旧 MCP metadata；本地比较不代替 MCP
鉴权。停止旧 ingest；receiving／cancelled 允许，已有 publishing／published 或其他
终态先沿原事实处理，不用新任务绕过发布。旧 pending 尾部不计入前缀。

```python
recovered = NativeRangeReceiver.recover_new_plan(
    old_session_path, old_full_transport_plan, new_full_transport_plan,
    {i: actual_preserved_part_path[i] for i in range(committed_part_count)},
    output_dir=owned_new_output_directory, input_root="/mnt/data",
    target_name=new_unique_original_filename,
)
new_session_path = recovered.session_path
```

先创建可写的专用 output_dir，和 input_root 位于同一文件系统。helper 用 O_EXCL
和最多 64 KiB 块创建新段名别名，在写第一字节前持久化真实 inode，再正常 ingest。
新账本的不可变 intent 与 `recovery.json` 绑定；不修改旧账本，不从 partial 造缺段。
额外空间覆盖所有别名、新 temporary、可能的完整 publication copy 和既有预留。

复制或原生进程中断后，若原生文件系统仍在，沿同一新 nonce 续接：

```python
recovered = NativeRangeReceiver.resume_recovery(
    new_session_path, same_new_full_transport_plan, input_root="/mnt/data"
)
```

已记录归属的部分别名先核对 inode 和真实前缀，再继续余下字节；accepted 已提交
而映射未更新时，重新验算并以追加 0 字节对齐进度。普通 ingest 不绕过未完成的
恢复。创建后、归属提交前崩溃而无法确认 inode 时，拒绝接管并保留现场。
在 recovery ready 前保留旧 session 和段；之后按新 plan 顺序取剩余段并 finish。
如果新源计划也失效，用实际失败证据再次新建任务，不滑动旧期限。

上下文重启仅丢失 Python 对象时可恢复持久化 session。若账本及 receive.tmp
真实缺失、原生段仍在，使用下节重验入口；不能手造旧账本。必要原件字节实际
丢失时，缺失部分必须重新取回。cleanup 保留输入、别名和
`.native-range-recovery-<nonce>.json` 映射；最终回执的 `recovery` 记录两代 ID／nonce、
真实复用长度和映射路径。未知文件或归属不会被自动删除。

本固定资产的本地恢复和 SDK 交付回归不能替代 ChatGPT 200 MB 全取及合法恢复。
已有完整原生单文件路线证据仍须与最终集成包及生产验收分列；实际资格由绑定
完整载荷指纹的外部记录证明。版本号、助手 pin 与交付契约 SHA 都不是通过证据。
固定 profile 与摘要见 [原件交付契约](ORIGINAL_FILE_EXPORT.md)。

### 旧账本丢失，但真实原生段仍在

先只读核对旧 session/ledger/receive.tmp 是否存在，不凭旧回执宣称仍有正确前缀。
已知未决发布沿旧事实处理，不能用此入口跳过。源 ID 失效后仍从授权 MCP 取得
新计划；本地重验不授予新源权限，也不复活旧 ID。用户取消后不得自动新建任务。

`recover_detached_prefix` 使用真正保存的完整旧计划，逐段追溯它原来的 export ID
和文件名。允许 a0/a1 与 b2 混合，但每份旧完整计划都必须与新计划的来源范围、
整件长度/SHA、全部段几何及 SHA 一致。布局变化拒绝，不手改计划或跨范围拼接。

```python
r = NativeRangeReceiver.recover_detached_prefix(
    {old_a_plan["export_id"]: old_a_plan, old_b_plan["export_id"]: old_b_plan},
    new_full_transport_plan,
    {
        0: {"path": actual_a0_path, "source_export_id": old_a_plan["export_id"]},
        1: {"path": actual_a1_path, "source_export_id": old_a_plan["export_id"]},
        2: {"path": actual_b2_path, "source_export_id": old_b_plan["export_id"]},
    },
    old_input_root="/mnt/data", input_root="/mnt/data",
    output_dir=owned_new_output_directory, target_name=new_unique_original_filename,
)
new_session_path = r.session_path
```

路径来自真实物化文件。接收器重验每份真实普通单链接文件、受限根、inode、版本、
长度和 SHA；以 64KiB 块只新建 `0600` 新段名别名，保留原件，不 chmod 云端文件。
新 nonce、恢复绑定和复制 journal 均由正式接收器产生，不构造旧 ledger。
回执明确 `old_receiver_progress_claimed=false`、旧 nonce 为空，表示当前字节重验。

复制或 receive.tmp pending 途中停止后，沿实际新 session 调用前述
`resume_recovery(new_session_path, same_new_full_transport_plan)`；归属已持久记录的
partial 先核真实前缀，再成功继续，仍由正常 `ingest` 入账。未持久确认归属的别名、
源文件/root变化或未知文件必须拒绝接管并保留；不得改账本或删除它们来凑成功。
旧正确片段及来源计划保留到新恢复 ready，最终仍须 `finish` 完整重新验算。

### 固定串行编排与有限重试

用户可以说“把指定原件取回到原生环境，并核对长度、SHA、ZIP 和图片”。助手
负责调用当前连接的 MCP 工具；原生 Python 仅处理它已经真实收到的文件，不具有
未授权 MCP/网络能力，也不从模型输出拼 Base64。

固定顺序为：当前范围和源身份检查 → 新计划/可信 helper → 原生核 helper 摘要 →
领取一个实际段 → 原生独立长度/SHA → `ingest` 成功入账 → 下一段 → 整件独立
长度/SHA/ZIP/实际解包和看图 → 源取消及终态资源释放 → 按清单安全清理。
保存完整计划、新 session 路径和每次实际回执，状态查询只读 metadata，不触发取件。

同一逻辑段普通超时、重置或截断，首次失败后最多再尝试两次并留间隔；有效计划
复用同一绑定、幂等 key，不把部分发送算接收。源拒绝、身份/来源变化、hash错误、
确认拒绝或用户取消不按网络错误自动重试。计划失效时合法新计划重验真实前缀；
它不延长旧期限。预算耗尽后保留前缀和对应请求证据，定位具体层，不无限重传。

时间分别记录准备、网络/实体化、工具编排、原生验算、恢复与最终验证；完整预算
为这些实测值及有界重试之和，不能只计源发送时间。新 v3 helper 本地回归通过仍
不等于 ChatGPT 原生导入、200 MB 或生产验收通过；资格继续绑定外部实际证据。

## 收齐后发布与回执

```python
receipt = r.finish(require_zip=True)
print(receipt)
```

整件长度／SHA 独立重新读取一致后才 no-clobber 发布，绝不覆盖已有目标。`require_zip=True` 应在首次 finish 指定，用于完整成员 CRC 检查；随后由原生工具解包和读图。非 ZIP 使用 `finish()`，按格式另做实际消费。

只有 `published_verified` 回执才有成功文件路径，记录真实最终长度、SHA、publication 方式、全量回读和 ZIP 检查状态。控制文件保存在输出根的独立 nonce 小 JSON，不依赖模型复述。临时接收、ready、部分文件、发布中的文件或 source send 结束都不是成功成品。

空间检查包含剩余原件、可能的完整 publication copy、账本预留和最低空闲；已经物化的段和 partial 占用会反映在实际 free。不会提权或提高平台磁盘配额。link 建立后提交前中断，可凭同 inode／全 SHA 恢复；fallback 创建后的归属无法确认时保持现场，不自动接管别人的文件。

## 取消和清理

成功后，先按主流程取消服务端 export、查询到实际资源释放。它只释放服务快照／引用，不删除原生环境成品。

```python
r.cleanup()  # 清自己的 temp／ledger／session，保留 final、输入段、小 JSON 回执
```

未收齐而决定取消：

```python
r.cancel()
r.cleanup()
```

输入段、最终文件和回执按本次准确验收清单另行清理。额外未知文件、inode、nonce 或已提交 hash 改变时拒绝清理；只读云端文件不 chmod 或提权。接收器本地测试通过不等于网页原生验收，当前完整 24 MB／200 MB 验收状态见 [原件交付说明](ORIGINAL_FILE_EXPORT.md)。
