# 独立发布源码快照

`0.4.2-files.1/` 是已完成隔离验收的原文件保存源码、25 个回归测试文件及便携文档。它独立于仓库主目录的其他开发功能；归档不等于自动部署，也不继承任何本机项目授权、账号或目录。

源码和公开使用说明与验收候选逐文件一致。测试用 development marker 保持关闭强制发行模式；构建器生成 candidate/rollback 的正式 marker。因此不要直接用归档目录启动生产。

## 本地验证

在独立的 Python 3.12 环境中按本快照的 `requirements.lock` 安装依赖，然后从快照目录执行：

```sh
cd versions/0.4.2-files.1
python -B -m unittest discover -s tests -v
```

进程退出证明和发布行为的当前验收平台为 macOS arm64。测试自行创建、清理临时合成数据；仓库不保存验收附件、实际配置、密钥或原始会话。

## 复现固定候选与兼容回滚

仍在快照目录执行下面的命令，输出目录必须尚不存在。此操作只构建文件，不启动服务或修改本机授权：

```sh
python -B - /absolute/path/to/new-release-pair <<'PY'
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
PY
```

核对最终指纹：

| 包 | 内容指纹 |
| --- | --- |
| candidate | `5a9ee7e1ed2c1c811384b79e374133b52a6e33e64db80f59d6cb212bfa835982` |
| rollback | `2af308177c4b85c8df6a2e8290624575fa962cd9fbede740ff8c50ccd6faddc4` |

使用 `python -B tools/build_file_release.py --verify /absolute/path/to/package` 校验，再与上表独立比较。完整逐文件清单在各包的 `manifest.json`；本表和清单不是数字签名。

## 部署边界

按[原文件保存与回滚说明](0.4.2-files.1/ORIGINAL_FILE_SAVE.md)准备显式项目、历史、认证和原文件配置。实际配置必须留在发行包和版本控制之外。`BUILD_SPEC.json` 仅列公开源码文件，不包含机器设置。

生产从全新、已验证的运行副本启动 `run_release.py`，不要改动冻结发行包。Cloudflare 入口会在运行副本 `work/` 下写审计；运行产物与源文件指纹分开核对。认证、隧道和授权配置按部署环境明确安排，不由构建器修改。

**不要用归档的 `deployment/manage_services.py install` 执行仅重启源服务的升级。** 该兼容工具会操作源服务和隧道两项，且不携带原文件配置；本次原文件发布需要显式源服务启动定义。

兼容 rollback 固定只检查原文件任务、保持私有保护，不开放新保存／刷新／取消，不启动接收者。启用新私有保护后，不能用不理解该保护的裸旧版本回滚。保存只新建、不覆盖，已发布原件不会因回滚删除。
