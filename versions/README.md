# 独立发布源码快照

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
