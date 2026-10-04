# 可信接收器：把实际原生段写成一个原件

这是本包提供的静态 helper，不是业务 repo 中的代码。先调用 `get_file_export_transport_plan` 取得 `receiver_asset`，再调用 `materialize_file_export_receiver` 明确领取；账户本人处理平台确认。无需把 helper 放入业务 repo，也无需手动上传。

## 先在原生环境核验代码

代码资产的 `name`、实际长度和 SHA 以当前包的计划 metadata 为准。当前开发资产为 `native-range-receiver-v2`／`native_range_receiver.py`，55,892 字节，SHA-256：

`c2947336638742cf3471d55a349d89238aaa21316632cc6924d47a6b7623a1db`

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

上下文重启仅丢失 Python 对象时可恢复持久化 session；临时文件系统或必要原件／
控制文件丢失时，必须重新实际取回。cleanup 保留输入、别名和
`.native-range-recovery-<nonce>.json` 映射；最终回执的 `recovery` 记录两代 ID／nonce、
真实复用长度和映射路径。未知文件或归属不会被自动删除。

本开发资产已通过本地恢复和 SDK 交付回归；固定集成包仍须完成 ChatGPT 200 MB
全取与计划到期恢复验收，当前不据此宣称生产容量正式生效。

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
