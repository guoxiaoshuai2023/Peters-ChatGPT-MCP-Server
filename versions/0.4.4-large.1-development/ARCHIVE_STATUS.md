# Development archive — final integration acceptance incomplete

本目录是 `0.4.4-large.1-development` 开发归档，**最终集成验收未完成**，不作为生产发布。已有完整 200,000,000 字节路线证据不能代替本集成版本或生产验收。

本目录的可执行 Python 与冻结隔离测试载荷逐字节一致。相对于测试载荷，README 和 MIT 版权显示已脱敏；这两项资料差异使本目录不能被当作同一个完整载荷。测试只保留合成回归源码，不保存验收原件。

- Frozen development test payload SHA-256: `d7b96f5b76fc1e3ab75c5a777b63197c1012b044df4303c20796726257449f6e`
- Delivery profile: `chatgpt-web-gpt56sol-high-streamed-resource-200mb-development-v1`
- Profile evidence status: `development_unverified`
- Package build snapshot ID: `development-test-integrated-recovery-20261004-r2`

该指纹属于固定的 candidate 测试载荷，不是本归档目录或 Git commit 的指纹。BUILD_SPEC 保留开发状态，不授予生产资格。构建器会生成 private-config guard 和发布模式 marker；不要直接运行开发源码代替部署固定包。

接收路线允许使用真实原生片段，由接收助手核对并流式组装为单个文件；不宣称平台支持单个 200 MB 附件一次实体化。必须完成最终集成版本完整原生接收、正常取消/资源释放及恢复验证，再进入生产发布。生产还须独立验收 200 MB 原件及既有授权审核包。

本开发分支不改变仓库默认入口、现有生产版本、任何标签、机器配置或授权；clone 后须独立配置项目目录、身份及访问范围。
