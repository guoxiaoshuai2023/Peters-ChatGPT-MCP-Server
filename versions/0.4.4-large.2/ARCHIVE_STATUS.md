# Frozen candidate source archive — native integration acceptance pending

本目录归档 `0.4.4-large.2` 的固定待验源码，**最终集成验收未完成**。候选与兼容回滚载荷已冻结并通过完整内容核对，部署状态仍为 `prepared-not-deployed`；包冻结、版本号、契约摘要及构建成功均不授予原生资格或生产资格。

`BUILD_SPEC.json` 明确选择的 41 个源码与便携资料文件，与固定 candidate 和 rollback 的对应文件逐字节一致。额外合成测试、开发 marker、构建器、本说明、BUILD_SPEC 和 CODE_IDENTITY 不属于发行载荷；整个归档目录和 Git commit 不冒充下表载荷。

| 身份 | SHA-256 |
| --- | --- |
| Candidate payload | `072b2a7f294fa92bc02d8c2e4e2c1251d2cdbbbdd6014a630f4422e7b1cb4e0e` |
| Compatible inspection rollback | `822af9113e6c6bd44eb7a65519a9e8902c4615298d3f994299a5adc1bd8b921d` |
| Included source content | `e26b2451699bbc33e7ea29dd7644223283cb75845e82e9ba9701778a89170eb7` |
| Delivery contract | `b505b56964c279e5824a239c1b5a19104b9f403bd0d5c027955cfd591c51eb0b` |

交付 profile 为 `chatgpt-web-gpt56sol-high-native-raw-part-200mb-v2`。包内固定 helper 为 `native-range-receiver-v3`，64,205 字节，SHA-256 为 `58b6e24a5ebb08f4bd5ffe2f33c23a8202537f49eaa9c582b83ef8ec0567bd84`。规范契约与 helper 实际字节已独立核对一致；它们只标识当前固定代码，不是原生验收通过证据。

本归档沿用上一版本目录结构，增加旧账本缺失时重验真实原生前缀的合成回归。源码、配置示例及便携资料保留；真实原件、输入包、原始工具证据、运行目录、凭据和本机授权配置不归档。归档 BUILD_SPEC 记录确认的固定包身份；开发源中的待冻结 BUILD_SPEC 不因此被修改。

`requires_native_evidence`、空的 `verified_mime_types` 和未观察到的当前原件完整接收事实保留待验状态。最终验收需要由 ChatGPT 原生环境实际接收全部分段，形成精确 200,000,000 字节且 SHA 与来源一致的完整单文件，独立检查 ZIP、解包、读取图片，并验证正常取消、资源释放和合法恢复。已有路线成功证据不能代替本固定载荷验收；生产版本与既有授权审核包仍须分别验收，Pro 未验证。

包内接收器按真实原生文件重验前缀，使用正式的新计划、session 和恢复账本；不手造旧进度、不复活失效 ID、不修改账本来凑成功。固定串行编排与有限重试见 `NATIVE_RANGE_RECEIVER.md`。本地合成测试通过不能代替网页原生验收。

使用 BUILD_SPEC 的显式 include 和 snapshot_id，可在尚不存在的新输出目录重建固定 candidate / compatible inspection rollback；随后通过构建器 `--verify` 独立比较完整指纹。构建不启动服务或授予本机范围。构建器生成保护配置与模式 marker，不直接运行开发源码来替代固定发行包。克隆后须独立配置目录、仓库身份、私有根及访问授权。
