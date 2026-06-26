# 贡献指南

`nimsodium` 应保持小而高层，并尽量避免被误用。

欢迎贡献，尤其是测试扩充、文档、示例、不同 OS/Nim/libsodium 组合下的运行确认报告、CI 改进、打包修复和维护更新。也欢迎提交运行确认中发现的问题报告，以及基于这些报告的 bug 修复。

## 适合开始的贡献

- 改进现有 workflow 的示例
- 为非法输入和失败路径添加测试
- 在特定 OS、Nim 版本或 libsodium 版本上验证安装和测试
- 改进文档、翻译或 release notes
- 基于稳定的 upstream reference 添加 known-answer tests
- 为新的 libsodium 或 Nim release 更新维护说明

## 涉及安全的变更

修改以下内容前，请先创建 issue 或 design note：

- 公共加密 API 的形状
- 已存储的二进制格式
- 密码加密参数
- nonce、salt、tag 或 header 的处理
- key derivation context 或 typed key 行为
- raw FFI declarations
- authentication failure behavior
- file output replacement behavior

不要把涉及安全的变更作为没有说明的重构提交。请说明 use case、涉及的 raw libsodium symbols、预期的失败模式，以及证明难以误用的测试。

## 设计规则

- 不自行发明加密算法。
- 不把完整的 raw libsodium API 作为主 API 暴露。
- 常见任务中不要让调用者直接管理 nonce、MAC tag 或 output buffer。
- 不使用 generic hash 存储密码。
- authentication 失败时不返回 plaintext。
- 新的 public high-level API 不增加 string-based key parameter。使用独立的 key type 和 checked constructor。
- 检查每一个可能失败的 libsodium return code。
- 从 `nimsodium/errors.nim` 抛出 package-specific exceptions。
- 优先覆盖安全 workflow，而不是追求 raw symbol coverage。

## 测试

```sh
nim check --path:src --nimcache:/tmp/nimsodium_nimcache src/nimsodium.nim
nim check --path:src --nimcache:/tmp/nimsodium_nimcache src/nimsodium/advanced.nim
nim c -r --path:src --nimcache:/tmp/nimsodium_nimcache tests/test_nimsodium.nim
env NIMBLE_DIR=/tmp/nimble nimble check
```

发布前也请验证文档生成。

```sh
nim doc --project --index:on --outdir:/tmp/nimsodium_htmldocs --path:src src/nimsodium.nim
nim doc --outdir:/tmp/nimsodium_htmldocs --path:src src/nimsodium/advanced.nim
```

如果内容可能涉及漏洞，请按照 [Security Policy](../SECURITY.md) 报告。不要在 issue 或 pull request 中包含真实 secret、token、password 或 private key。
