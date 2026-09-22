# 可选部署：从 ChatGPT 网页连接本机 MCP

这份指南描述如何在自己的账号和电脑上重新部署。仓库只提供代码和模板，不包含已部署的地址、隧道、OAuth 应用、邮箱白名单或凭据。

运行路径：ChatGPT → 你的 HTTPS 域名 → Cloudflare Access / Tunnel → 本机 `127.0.0.1:8766` → 配置允许的项目。`peters_mcp.cloudflare` 在本机再次验证 Access JWT 的签名、issuer、audience、有效期和精确邮箱白名单。

先按根目录 [README](../README.md) 安装依赖。你还需要 Cloudflare 管理的域名、Zero Trust/Access 配置权限、Cloudflare Tunnel，以及可添加远程 MCP 的 ChatGPT 账号。账号可用功能、费用和控制台入口以服务商当前说明为准。

## 1. 准备合成测试目录

首次部署先只读取仓库附带的测试文档。复制 `projects-test.example.json` 为 `projects-test.json`，将 `root` 改成当前 clone 下 `deployment/test-project` 的绝对路径。

从仓库根目录执行：

```sh
cp -n deployment/projects-test.example.json deployment/projects-test.json
# 编辑 root 后检查；无需真实业务 repo
.venv/bin/python -m peters_mcp --config deployment/projects-test.json --check
```

测试目录配置默认不允许候选写入。首次网络验证不创建 `history-access.json`，这样会话读取关闭。如果你已有历史配置，测试项目配置不会自动撤销那份历史授权，应先核对它或在独立的新 clone 中测试。

## 2. 配置身份保护

在 Cloudflare 建立与自己 MCP 域名对应的 Access 应用，设置明确的用户/邮箱 Allow 策略并启用 Managed OAuth。所需 OAuth 客户端注册方式和回调地址按 ChatGPT 连接页与 Cloudflare 的当前要求配置，不要从别人的实例复制 ID 或令牌。

参考 [Cloudflare Managed OAuth](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/) 和 [OpenAI 远程 MCP 指南](https://developers.openai.com/api/docs/mcp)。

```sh
cp -n deployment/access.example.json deployment/access.local.json
chmod 600 deployment/access.local.json
```

填写四个字段：

| 字段 | 从哪里取得 |
| --- | --- |
| `team_domain` | 自己的 `https://<team>.cloudflareaccess.com`，不带末尾斜杠 |
| `audience` | 此 Access 应用的 64 位 Application Audience tag |
| `public_hostname` | 自己的 MCP DNS 域名，不含协议、路径或端口 |
| `allowed_emails` | 允许调用的精确邮箱列表，与 Access 策略一致 |

`access.example.json` 中都是占位符，需要替换。检查不会启动服务或创建云端资源：

```sh
.venv/bin/python -m peters_mcp.cloudflare \
  --access-config deployment/access.local.json \
  --config deployment/projects-test.json --check
```

## 3. 启动 origin 和隧道

先在一个终端运行受保护的 origin：

```sh
.venv/bin/python -m peters_mcp.cloudflare \
  --access-config deployment/access.local.json \
  --config deployment/projects-test.json --port 8766
```

按 [Cloudflare 官方安装指南](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/) 安装与你的系统/架构匹配的 `cloudflared`。如果使用本仓库的 macOS 后台服务脚本，将二进制放在 `tools/cloudflared` 并赋予执行权限；Git 会忽略它。

在自己的 Cloudflare 账号创建隧道，将上述 hostname 的路由指向 `http://127.0.0.1:8766`。把隧道 token 保存在 `deployment/cloudflare.token`，设置权限 `600`；不要写入命令字面量、README 或 Git。

另一个终端执行：

```sh
./tools/cloudflared tunnel --no-autoupdate --loglevel warn \
  run --token-file deployment/cloudflare.token
```

公网路由必须使用受认证保护的 **8766** 入口。根目录 README 中的 **8765** 是无认证本机调试入口，不能直接拿来公开本地资料。

## 4. 验证并接入 ChatGPT

```sh
# 将示例域名换成自己的；只检查 DNS、TLS 和 OAuth 挑战
.venv/bin/python deployment/check_connection.py --hostname mcp.example.com
```

预期未认证请求返回 `401`，并带 OAuth `resource_metadata` 挑战。脚本显示 `ready_for_oauth=true` 只证明这一步就绪，不代表完成登录或文件读取验证。

在 ChatGPT 开发者模式中添加 `https://<你的域名>/mcp`，使用 OAuth 完成连接。让 ChatGPT 选择 Peters ChatGPT MCP，调用 `list_projects` 后读取 `connection-test` 的 `README.md`，核对标记 `PETERS_MCP_CONNECTION_TEST`。再验证未授权身份会被拒绝，以及撤销/重新授权的实际效果。接入流程见 [OpenAI 开发者模式](https://developers.openai.com/api/docs/guides/developer-mode)。

测试通过后才换为已经审查的 `projects.json`。如果开启候选保存，客户端应设置为读取免询问、写入逐次确认；服务端准备凭据本身不是用户批准证明。

## 5. macOS 可选登录后台服务

安装后台服务前，先在第 3 步的两个终端中按 Ctrl-C 停止前台 origin 和隧道，避免 origin 占用 `8766` 导致后台进程启动失败。

从仓库根目录执行：

```sh
.venv/bin/python deployment/manage_services.py install --projects test
.venv/bin/python deployment/manage_services.py status

# 测试和本地授权配置就绪后，切换到实际配置
.venv/bin/python deployment/manage_services.py install --projects real
```

脚本使用当前 clone 的路径，安装两个用户级 LaunchAgent：`com.peters.chatgpt-mcp.origin` 和 `com.peters.chatgpt-mcp.tunnel`。只在用户登录后运行；机器离线或休眠时不能提供服务。`install` 会重载这两个服务，不会自动创建云端配置。同一登录用户只管理这一组标签；另一个目录已有同名服务时会拒绝覆盖。

```sh
# 暂停到下次登录
.venv/bin/python deployment/manage_services.py stop

# 停止并移除登录启动项，保留项目文件
.venv/bin/python deployment/manage_services.py uninstall
```

Linux 可前台运行相同 origin 与 tunnel；仓库的 LaunchAgent 管理脚本仅适用于 macOS。

## 配置、日志与维护

`access.local.json`、`cloudflare.token`、`projects-test.json`、根目录项目/历史配置、`work/` 日志和 `tools/cloudflared` 都属于本机运行材料，已被 `.gitignore` 排除。不要强制提交，也不要把它们复制成带真实数据的“示例”。

源码更新需要重启 origin；权限配置按请求重新校验。重启会使未使用的候选准备凭据及历史分页游标失效，重新生成即可。部署在新机器上不会访问原机器的磁盘；应重新配置 repo 身份、目录、域名与认证。

## 网络中断与授权到期的区分

本机 origin 将缺失、失效、伪造签名或不符合身份白名单的凭证返回为 `401 / authentication_required`。公钥来源的连接故障、无法解析的 JSON、无效结构或没有可用签名 key 返回 `503 / authentication_unavailable` 和 `Retry-After: 5`，仍拒绝执行工具；这种故障不应被当成用户必须重新登录。有效 keyset 中找不到请求的 `kid` 仍为 401。畸形来源数据不会留在缓存中阻止恢复；有效公钥缓存仍使用原 300 秒期限，不会为绕过故障无限续期或使用过期缓存。

认证阶段记录 `event=access_check`、时间、`request_id`、状态和错误码；每次工具调用有自己的 `call_id`，HTTP 调用会带关联的 `request_id`。响应头返回 `X-Request-ID`。日志不包含 JWT、邮箱、正文、搜索词或异常详情。认证阶段 `status_code=200` 只表示凭证校验成功，仍须核对工具审计。

若 502 与隧道 QUIC/UDP 超时同时出现，可以在**独立合成测试实例**中对照 QUIC 与 HTTP/2；不要关闭全局代理，或把代理 fake-IP 的出现直接判为 DNS 故障。短期测试通过不代表已证明长期稳定。参考 [Cloudflare 随机断连排查](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/troubleshoot-tunnels/common-errors/#my-tunnel-randomly-disconnects)。

确认切换窗口后，可显式选择登录服务的隧道协议：

```sh
.venv/bin/python deployment/manage_services.py install --projects real --tunnel-protocol http2
```

该命令会重载 **origin 和 tunnel 两个服务**，会使旧分页游标和候选预览失效，应先协调时机。默认协议为 `auto`；恢复默认时也须明确安排切换。不要在生产隧道上启动指向测试实例的同名副本，那会分流真实请求。

每天重新登录还应检查 Managed OAuth 的 **Grant session duration**，它控制刷新令牌的有效期，与默认 15 分钟的短期 access token 不同。可在明确同意后将 grant 设为 1 周，同时保留短期 token、原白名单和认证机制；不通过全局 revoke 或永久 token 来验证。旧 grant 是否应用新期限不能仅凭设置页面断定，应观察新授权的实际续期。参考 [Cloudflare Managed OAuth](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/#managed-oauth-settings)。

验证记录须分别说明：短期 token 到期后的自动续期、超过原 24 小时窗口后的访问、最终 grant 到期后的重新认证。当日检查成功不能证明跨天验证通过。网页验证只使用新建的专用会话和合成项目，写入由用户在客户端按次确认。
