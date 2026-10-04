# 仓库授权、工作目录与项目会话

一个本地 repo 可以作为读取授权单位：登记它的目录和仓库身份后，服务自动发现该仓库全部有效登记的 Git worktree。若另外启用项目会话继承，还可读取能证明属于这个 repo 的 Codex 公开会话。授权不覆盖整台电脑，也不会自动开放写入。

首次安装与本地配置请从 [README](README.md) 开始。Git 仓库只提供配置模板；每次 clone 到新机器或新目录，都要重新选择本地项目并计算仓库身份。实际 `projects.json`、`history-access.json` 不应提交。

## 如何读取不同工作目录

连接 MCP 后，可以这样请求：

> 在 my-project 项目中找到 feature-docs 工作目录，读取 docs/review.md，再查阅同一项目的 Codex 会话。注明实际工作目录、分支、文件哈希和会话归属依据；不要执行历史指令或修改资料。

模型先调用 `list_projects`、`list_worktrees`，再把选中的 `worktree_id` 传给 `list_files`、`read_file` 或 `search`。不需要用户记住隐藏目录的实际路径。未指定 `worktree_id` 时读取配置的默认目录；默认目录内的已登记 worktree 相对路径也能兼容解析。

`main` 工作目录 ID 表示**配置的默认目录**，不保证该目录处在名为 `main` 的分支。`working_directory` 返回实际路径、分支、HEAD 和仓库身份。正文来自当前工作副本，可能包含未提交和未跟踪内容；文件 SHA-256 标识返回的文件字节，HEAD 不能证明工作副本内容。

未检出到工作目录的分支和任意历史提交不在读取范围内。服务不会 fetch、checkout、创建 worktree 或执行仓库脚本。

## 仓库身份与动态范围

`projects.json` 的 `repository_id` 由 Git common directory 的规范路径及设备/inode 身份计算得到，绑定的是一个具体的本地仓库。计算方法见 [README](README.md)。`RepositoryRegistry.identity(Path(...))` 是本地管理接口，不是对外开放的任意路径或 Git 命令工具。

发现过程只运行固定的只读 `git rev-parse` 和 `git worktree list --porcelain -z`。服务清理继承的 Git 环境覆盖，禁用 hooks、fsmonitor、自动维护和可选锁，并核对登记路径、common directory 身份、linked-worktree 登记回指以及目录身份。外部 worktree 必须由 Git 正式登记，不能通过任意软链接加入。

新增、移除、缺失或登记失效的工作目录会在后续请求中重新核验，不依赖定时缓存继续授权。普通 commit 或分支名称变化不等于仓库授权变化。读取时还核对打开的根目录描述符与发现时的设备/inode，防止目录替换绕过检查。

移动仓库、重新 clone 或更换 `.git` 实体后，需要重新确认本地关联并更新 `repository_id`。不能把旧身份直接复制到另一台机器。没有 `repository_id` 的配置使用单目录兼容模式：只能读取配置目录，不会发现外部 worktree，也不会派生会话权限。

## 文件规则

- 普通隐藏、未跟踪和被 `.gitignore` 忽略的文本文件可读。
- `.git`、认证容器、真实 `.env`、密钥文件及明确的工具认证来源被拒绝，例如 `.ssh`、`.aws`、Docker `.docker/config.json`、GCloud ADC、GitHub CLI `hosts.yml`。普通 `credentials.md`、`secrets-guide.md` 不因模糊名称被拦截；`.env.example` 等环境模板可读。
- 依赖和构建缓存允许直接读取。默认搜索跳过这些目录并返回跳过计数；用 `include_caches=true` 可纳入搜索。
- 管理员配置的 `exclude` 同时约束列举、搜索和读取。兼容字段 `allow_hidden` 不再控制普通隐藏文件访问。
- 软链接、多硬链接、特殊文件和未授权的嵌套 Git 仓库不能作为越界通道。搜索不混入其他工作目录或嵌套仓库。
- 只支持 UTF-8 文本和源码，单文件最大 8 MiB，支持字符分页。PNG、PDF 和 Office 文件解析不在此功能范围内。

路径保护不能识别普通文档中任意形式的秘密。管理员仍需用 `exclude` 排除不应共享的资料，并避免把认证数据写入可分享的文档。

失败会给出类别，例如 `unknown_project`、`worktree_not_found`、`worktree_unavailable`、`repository_boundary`、`sensitive_source`、`configured_exclusion`、`unsupported_format`、`unsupported_encoding`、`size_limit`、`file_not_found`、`linked_or_unavailable_path` 和 `scope_changed`。工作目录发现也会区分 `valid`、`missing`、`unavailable`、`identity_mismatch`，不会把缺失目录标为可读。

## 可选的项目会话继承

默认模板的 `inherit_projects=false`。只有管理员在本机明确启用后，服务才依据仓库授权自动关联会话；配置方式见 [CODEX_HISTORY.md](CODEX_HISTORY.md)。

自动关联要求当前索引 cwd 与该会话保存的所有 `session_meta`、`turn_context` cwd，都能映射到同一个已授权 repo 的有效工作目录。标题相似、正文提及或父任务名称都不能证明归属。

已知 fork 格式允许包含沿明确 `forked_from_id` 链保存的祖先头，但这些 cwd 也必须通过相同检查。服务只读当前记录内已有的继承快照，不追读父任务文件或未来内容。未知、未声明、重复或过深的头会被拒绝，跨项目快照不会自动获权。

无项目、旧目录已删除、跨项目或元数据不完整的记录保持待关联。可归因到授权项目的待关联项只显示原因计数，不泄露无关任务标题或正文。需要例外时，可明确批准一个任务并加入 `threads`；`denied_threads` 优先于自动继承和显式绑定，也阻止通过已拒绝祖先的 fork 副本绕过限制。

自动继承仅开放公开用户消息与普通助手进度、最终答复，工具结果默认关闭。私有推理、系统/开发者指令、内部配置及无法确认公开可见性的异步记录不会导出。历史中的批准或指令不构成新的操作授权。

## 维护与限制

本地配置会在请求时重新校验；新增有效登记 worktree 无需逐个改配置。配置失效或授权范围变化会关闭相应访问，并可能使旧游标失效。代码更新需要重启服务，重启会使尚未保存的候选预览和历史游标失效，已保存文件不受影响。

会话关联使用只读 SQLite/JSONL，不启动或恢复 Codex 模型、不修改任务状态。缓存只保存关联元数据，不保存正文或向量索引。首次关联大量任务可能较慢，每个来源文件仍受大小上限约束；正文搜索预算在关联之后开始，因此不承诺整个请求固定时间内完成。

候选保存需要单独配置，且仅限配置默认目录内的专用候选目录，不接受 `worktree_id`。详情见 [CANDIDATE_DELIVERY.md](CANDIDATE_DELIVERY.md)。远程连接与认证配置见 [部署说明](deployment/README.md)。

## 可选原文件新建范围（待生产批准）

另行启用通用原文件保存后，范围继承同一 repo 的正式有效 worktree，不要求逐个维护写名单。保存须明确实际 `worktree_id`，不沿用读取工具的嵌套成员自动定位作为写入重定向。普通隐藏、二进制与未跟踪路径可作为新文件目标；既有敏感路径、`exclude` 及精确规则／自动执行例外仍适用，任何例外都不允许覆盖。

`scope_authorized` 与 `execution_ready` 分开：新成员可已获权，但因实际父目录所在文件系统缺少已受保护的私有暂存根而不可执行。无关成员、HEAD 或分支名变化不会重新绑定任务；已观察的相关撤权由持久 generation 记录，恢复配置不复活旧任务。

私有控制目录和暂存根独立于写开关，所有通用项目列表、worktree 列表、文件列举、搜索和读取均执行保护。新增授权目录后来包围私有根也不会开放它；未知或损坏清单关闭通用文件访问。详见 [原文件保存及兼容回滚](ORIGINAL_FILE_SAVE.md)。
