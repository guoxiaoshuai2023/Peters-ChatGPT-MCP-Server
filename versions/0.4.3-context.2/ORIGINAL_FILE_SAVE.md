# 通用原文件保存：候选版本使用与回滚

状态：隔离开发候选，等待生产批准。本文不表示功能已经在生产启用。当前操作系统验证范围为 macOS；Linux 等平台的发布原语、持久化和恢复行为尚不能按已验收平台宣传。

## 正常使用

ChatGPT 先生成实际附件，调用 `get_write_capabilities` 查看可用 repo/worktree，再用 `inspect_file_destination` 检查明确的相对路径。检查结果中的 `destination_display` 和 `target_version` 供后续保存调用核对；检查不会锁住路径，也不是批准凭证。

通过客户端的写操作确认策略调用 `save_generated_file`，传入原生 `file` 引用、明确的 `project_id`、`worktree_id`、`path`、检查得到的目标字段和唯一 `request_key`。不要让模型编造下载 URL、哈希或文件长度。只有确实已知时才提供 `expected_sha256`、`expected_size_bytes`。

服务持久接受请求后返回任务标识。`accepted` 只表示任务已接受，必须继续用 `get_file_save_status` 查看下载、发布、持久化和独立回读证据。响应丢失时用原来的 `request_key` 查询或重试相同意图；不要换一个新 key 猜测上次是否写入。

- 一个任务保存一个普通文件；没有多个文件的跨路径原子事务。
- 只新建。目标已有文件、目录、链接等任何项都返回 `target_exists`，即使字节相同也不会冒充本任务保存成功。
- 文件字节原样保存，不改换行、不加注释、不重编码、不转码、不解压 ZIP、不执行文件。
- 文档、代码、图片、音视频和其他二进制格式不受读取接口的 UTF-8／8 MiB 限制。本功能不设置固定文件大小或累计字节配额；实际磁盘、文件系统和协议限制仍存在。
- 普通隐藏文件允许，既有敏感路径保护和管理员 `exclude` 仍有效。所谓任意格式并不豁免 `.pem`、`.key` 等现有凭据路径规则。

保存代码或任务配置可能被 repo 自己的监控／构建程序响应；MCP 本身不会运行它们。

## 授权范围和就绪条件

登记了 `repository_id` 的 repo 自动覆盖其当前及后续正式登记、身份有效的 worktree。另一个 clone、同名目录、相同远端或伪造 `.git` 指针不能继承该身份。无仓库身份的兼容配置仅覆盖配置目录。

保存必须指定实际 `worktree_id`；`main` 是配置默认目录的标识，并不代表 Git 分支名。遇到默认目录内的另一个 worktree，检查接口可提示明确的成员选择，但不会把已经接受的任务自动改投。提交、分支改名和无关成员增减不应使冻结目标失效；相关成员移除、根替换或路径政策撤销会阻止继续发布。

`scope_authorized=true` 表示目标属于授权范围；`execution_ready=true` 才表示当前运行条件允许接收。新 worktree 位于另一文件系统而缺少已配置的私有暂存根时，可以属于授权范围但尚不能执行。这不需要重复申请 worktree 授权，却需要管理员配置该文件系统的私有运行条件。

`exclude` 按实际 worktree 根内的逐级相对路径和单独名称进行不区分大小写的 fnmatch 匹配。Git、认证容器和服务控制面固定受保护。规则、CI、任务／自动执行配置默认拒绝，只有管理员配置的精确 project/worktree/path 例外可以允许；例外不会解除固定保护或允许覆盖现有项。具体规则由能力接口列出。

## 后台执行、取消和来源失效

已接受任务可在离开会话后继续。普通登录令牌到期不等于撤销已接受任务；服务无法保证立即感知所有外部 OAuth 撤销。每次控制调用重新认证，后台任务按已可靠观察并记录的撤权、取消和资源条件处理。查询时使用当前身份；job ID 本身不是授权。

`cancel_file_save` 是写操作：取消尚未发布的任务，并在确认原写者停止之后清理确定归属的暂存。若已经发布，则报告发布事实，不删除成品。状态不明确时不能以取消成功推断文件从未出现，也不能擅自重复写入。

签名下载 URL 只存在于受控内存中，不进入日志、任务数据库或回执。它过期或服务重启丢失后，可能需要 `refresh_file_source` 提交新的实际附件引用，并匹配 `expected_source_revision`。刷新之前必须停止旧接收者；不能修改原目标或已绑定的内容约束。

首版没有提供方不可变版本适配，也不做 HTTP Range 续传。已绑定 `expected_sha256` 的同内容任务可按状态允许从头接收新引用并验证完整哈希；没有可靠同内容依据时，新 URL、相同文件名、长度、`file_id` 或 ETag 都不能证明原件相同，需要新的内容任务。不能把旧前缀和新响应直接拼接。

下载只接受可核验完整性的 `Content-Length` 或合法 chunked 响应。仅靠关闭连接表示结束的 close-delimited 响应返回 `completion_unverifiable`，不会把 EOF 当作原件已完整接收。已知错误响应、非预期部分响应和隐式内容编码也会拒绝。

回执区分接收哈希、目标回读哈希、预期哈希是否匹配、发布事实及持久化状态。模型提供的哈希匹配只能证明符合该承诺值，不能自动证明它来自生成端。没有独立来源证据时，不声称“生成端原件身份已验证”。

## 管理员配置与显式初始化

实际配置不随发布包分发，不放入业务 repo，也不提交 Git。先准备独立的 `original-files.json`。下例只有便携占位值，必须由管理员选择本机位置和准确来源域名：

```json
{
  "version": 1,
  "enabled": false,
  "control_directory": "/absolute/path/to/service-control",
  "spool_roots": ["/absolute/path/to/private-spool"],
  "sources": {},
  "special_exceptions": [],
  "min_free_bytes": 1073741824,
  "max_workers": 1
}
```

`min_free_bytes` 是保留可用空间的运行条件，不是文件大小配额。`sources` 只接受核准的精确 HTTPS 提供方，不从模型输入自动放宽；所有地址、重定向和实际连接仍需通过来源检查。

控制目录和每个暂存根必须位于所有授权项目／worktree、Codex 原始状态及历史目录之外，并具有各自明确归属。父目录由管理员准备。配置本身必须是普通、无链接、当前用户所有且不可被组／其他用户写入的文件，建议 mode `0600`。

在已批准的本机准备阶段执行：

```sh
python -m peters_mcp.file_setup \
  --file-config /absolute/path/to/original-files.json \
  --projects-config /absolute/path/to/projects.json \
  --history-config /absolute/path/to/history-access.json
```

未启用历史时省略最后一项。该命令只初始化并核验明确配置的私有基础目录，不启动下载 worker、不接受任务、不部署服务。它不会修复、清空或重置已有损坏状态，也不替管理员改宽松目录的权限。

所有活动服务和回滚实例必须使用同一保护锚点。私有根先登记保护，再经过读取屏障，最后激活；此前已开始的通用文件操作必须结束。仅启动一个新管理进程，不能使不认识保护协议的旧实例安全，因此必须先完成服务级切换安排。

清单缺失、损坏或身份不符时，通用项目查询关闭，不能以“暂时禁用写功能”为由继续无保护读取。禁用写入、删除任务或回滚都不撤销既有私有路径保护。状态查询是只读，不会自动重启下载或发布。

## 独立构建、内容核验和兼容回滚

构建器只读取操作者明确选定的源码快照。先审查要包含的相对文件列表，再对每项传入 `--include`：

```sh
python tools/build_file_release.py \
  --source /absolute/path/to/reviewed-development-snapshot \
  --output /absolute/path/to/new-release-pair \
  --snapshot-id original-file-candidate-review \
  --include peters_mcp/__init__.py \
  --include peters_mcp/__main__.py
```

上例仅示范参数，不是完整可执行文件清单。必须显式加入依赖闭包、所有必要保护／只读状态模块、许可、依赖锁和本文等必需文档；缺项构建会拒绝。构建器不会自动抓取整个工作区。需要额外防止个人或真实项目字串进入产物时，使用只在本机保留的 `--deny-text-file`；匹配失败不会回显敏感字串。

允许项限定为一层 `peters_mcp/*.py`、批准的公开说明、许可、依赖文件及便携 example 配置。实际配置、tests、runtime、审计、原始会话、内部设计稿、`.venv` 和 `.git` 均不在白名单内。内置扫描检查个人 home 路径、会话标识、临时入口、常见令牌和凭据字面值；扫描不能代替人工审查未知秘密。

产物包括 `candidate/` 和 `rollback/`，各有逐文件 SHA-256、排序内容指纹和源码快照指纹。两个包携带同一源码快照和保护实现，但生成的发行模式不同，因此最终内容指纹不同：

- candidate：写入仍取决于显式本机配置和可信调用身份，构建不等于启用。
- rollback：固定 `INSPECTION_ONLY=True`，仅装载保护及只读 `FileSaveInspector`，不启动写 worker，不开放新保存、刷新或取消工具。
- 两者均固定 `REQUIRE_PRIVATE_CONFIG=True`。即使直接运行模块而绕过 launcher，缺少显式私有配置也必须拒绝启动；运行参数不能把 rollback 恢复成写模式。

核验方式：

```sh
python tools/build_file_release.py --verify /absolute/path/to/new-release-pair/candidate
python tools/build_file_release.py --verify /absolute/path/to/new-release-pair/rollback
```

与审批记录中独立保存的指纹比对，而不只信任包内清单。该清单是完整性记录，不是发布者数字签名。验证后冻结包内容；不要在发行目录运行会生成测试、缓存或诊断文件的开发流程。

远程入口使用各包生成的 `run_release.py`，显式提供原有 `--access-config`、`--config`、`--history-config`、`--file-config`、监听端口等本机参数；认证配置不在包中。不得只为绕过检查而改成无认证的本机入口。

生产切换需要单独批准。切换前核对新旧内容指纹、保护锚点、授权配置、活动任务、真实读取证据和回滚可用性，协调短暂停顿。历史游标及旧候选预览可能因重启失效；已经保存的文件不会因此回撤。

兼容回滚必须先停止接收者并按协调记录确认退出，保留任务和发布事实，再以 rollback 包、同一保护锚点和配置启动。它不迁移／重建任务数据库、不清理未知暂存，也不继续写任务。只读检查只能报告已有可信记录；损坏或不兼容时明确报告不可核验。不要启动不认识私有保护的裸旧版本，不要删除私有目录来“恢复”读取。再次启用写入和任何清理另按明确的运行安排执行。

## 身份修复版本的任务恢复边界

私有清单v2使用卷UUID、文件ID和创建时间；spool选择仍要求与目标本次运行同设备，发布继续使用原有原子只新建机制。新任务额外保存runtime_epoch，不迁移SQL schema或既有任务body。

同boot及相关设备映射未变的服务重启可按既有状态机恢复。跨boot、卷映射变化或无epoch的未完成任务只读隔离，禁止自动接管、发布、撤权或清理。存在隔离/未决任务时拒绝新job；已有key的事实查询和同epoch合法任务继续分别判定，正常publisher不会被自身intent阻断。

非abort的发布intent存在但published=True尚未持久化时，状态观察可为unknown，不能从旧False断言未发布。当前有效publisher继续正常执行；失去执行者或被隔离的任务另报recovery_required。旧已完成事实不重写，目标不能复核时不伪造当前文件核验。

只读Inspector在打开SQLite前拒绝WAL、SHM、journal旁文件及非DELETE header，避免mode=ro仍创建共享内存文件。检查失败不尝试数据库恢复。兼容回滚保留当前DB、新旧请求键和发布事实，不能恢复旧DB备份来回退运行代码。
