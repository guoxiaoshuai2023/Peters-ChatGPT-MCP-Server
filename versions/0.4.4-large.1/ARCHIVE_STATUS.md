# Final contract archive — native integration acceptance pending

本目录归档 `0.4.4-large.1` 已定稿合同与固定待验载荷，**最终集成验收未完成**。合同定稿不等于生产资格；本次候选分支归档不执行生产部署。

本目录 BUILD_SPEC 明确选择的 41 个源码/便携资料文件，与固定最终候选源项逐字节一致；额外测试、开发 marker、本说明和 CODE_IDENTITY 不属于发行载荷。

| 身份 | SHA-256 |
| --- | --- |
| Candidate payload | `5722e0e89f15438b6bdfb65c1320d7f52a3aeb2e3eb292d41275ef86bbaf200f` |
| Compatible inspection rollback | `368dbe558ac23b3799c03e676d7acec0e1886de008b45aa93f4a1964a3667297` |
| Included source content | `85e72a900a381ec8d72fa8cd112a7bb3caa7c9448e1c96e89184cbf3ed34a45c` |
| Delivery contract | `cd2663c75f793900c0063866d2052fc8801f4f1d68b0b6f1f0a5b92d2007bd8e` |

交付 profile 是 `chatgpt-web-gpt56sol-high-native-raw-part-200mb-v2`。合同指纹不是验收 SHA。`requires_native_evidence`、空的 `verified_mime_types` 和未观察到的当前原件完整接收事实准确表示验收尚未完成，不能据源码上限宣称客户端支持已验证。

允许原生分段传输，最终必须形成精确 200,000,000 字节、SHA 与来源一致的完整单文件，并由原生工具独立验算、检查 ZIP、实际解包及读取图片。已有开发路线成功记录不能代替本固定最终集成包，也不能代替之后的生产 200 MB 和授权审核包验收。Pro 兼容性未验证。

使用 BUILD_SPEC 的明确 include 和 snapshot_id 可重建固定 candidate / rollback 载荷，输出须为尚不存在的新目录；随后以构建器的 `--verify` 检查完整指纹。构建器生成模式 marker；不要直接运行开发源码目录替代固定发行包。兼容回滚包会暂停新原件导出和新写入，保留私有保护及任务事实的只读检查。

克隆不继承本机配置、凭据、目录或授权，必须单独配置。此归档只保留必要源码、合成回归测试和便携资料，不保存验收原件、原始工具证据或真实业务资料。
