# 独立发布源码快照

最新修复快照为 [`0.4.4-progressive.2`](0.4.4-progressive.2/README.md)。它在 [`0.4.4-progressive.1`](0.4.4-progressive.1/README.md) 的 `raw-parts-v1` 基础上，将宿主交付的只读 helper/分片与当前用户的私有可写状态分开校验，并用唯一固定加载器在校验、关闭输入后执行同一源码缓冲。`.1` 保留为历史协议与旧附件归属检查的复现对照，不是推荐部署版本；`.2` 的快照内文和 BUILD_SPEC 保持冻结原字节。

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
cd versions/0.4.3-context.1
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
