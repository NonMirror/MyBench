# MyBench automated pwn/rev mutator and validator

这是一个针对 `CTFbench` 的自动化变异器和验证器雏形。它以
`development_dataset.json` 和 `test_dataset.json` 为唯一题目清单来源，自动发现
全部 `pwn` 和 `rev` 题目，不依赖人工维护题目路径。

当前实现覆盖异构题目：

- 有 C/C++、Go、Python、JavaScript/TypeScript 等源码的题目：对优先源码注入一个确定性的
  opaque guard。guard 通过 `volatile` 读取和实际调用增加运行时控制流，但其确定性条件为假，
  因此不会改变题目的正常输出；变异结果包含源码哈希和完整 provenance。
- C/C++ 源码旁边如果存在同 basename 的已部署可执行文件，生成器会在隔离的构建过程中
  重新编译该文件，并要求输出的格式和架构与 seed 一致；本机编译器不匹配时会尝试
  `docker:gcc:12-bookworm` 的 `linux/amd64` 静态构建（再回退到动态构建）。只有
  `compiled_artifact_rebuild` 成功且 hash、注入符号和 CFG witness 都通过，才把它计为
  可执行题目的实质变异。
- 对只有预编译原生入口、无法从源码重建的题目，或只有原生插件/内核模块而没有可执行
  wrapper 的题目，生成器会分析 `main`/`entry0` 及其他用户函数，把一个
  同长度的 x86 条件跳转或 AArch64 条件跳转改成无条件跳转，并重新计算 CFG witness。
  这条 `binary_cfg_mutation` 路径直接修改变体中的实际 ELF/Mach-O/PE，保留 seed 不变；
  没有可安全改写的分支时只记录 `binary_cfg_mutation_skipped`，绝不把 wrapper 当成变异。
- 不支持的源码语言、无法识别 C/C++ `main` 的源码以及没有候选源码的题目，会记录
  `source_mutation_skipped` 和原因。它们不会被注释、模块变量或其他无效果标记冒充成已变异。
- 如果源码不是声明的运行时文件、而且没有可兼容重建的已部署 artifact，源码修改会回滚并
  记录为跳过；不会留下“源码变了、实际运行 binary 没变”的假变体。
- 只有预编译 ELF、脚本、压缩包或自定义 VM 的题目：生成可执行的
  `run_variant.sh` 入口包装，注入可复现的 variant/parent 环境标识，并记录降级路径。
- `run_variant.sh` 和 `variant_runtime.json` 是运行时打包/元数据操作，不计作源码级的
  pwn/rev 变异。
- 所有变体都复制题目目录，但默认使用 hardlink + copy-on-write，避免为 110 道题重复
  占用数百 MB；写入变异文件前会先解除 hardlink，不会修改 `CTFbench`。
- 公共 `challenge.json` 会移除 `flag`、`answer`、`solution`、`secret` 和 `key` 字段；
  明显的 `flag`、answer、solution、test_solver 和 writeup 文件也会从变体目录移除，
  manifest 只保存 secret 的哈希。被选中的源码会执行上面的源码级变异；未被选中的
  源码和压缩包不会被自动重写，其中的内嵌常量会在 manifest 中明确标记为未脱敏，
  便于后续接入专门的 oracle 分离流程。
- 验证器检查题目清单文件、声明的题目文件、opaque guard 符号、变异哈希、入口包装和
  manifest 一致性，并重新读取二进制补丁位置、哈希和 CFG witness。报告中的
  `substantive_artifact_mutations` 单独统计真实部署制品变异，避免“验证通过”被误读为
  “每道题都发生了实质变异”。`--build` 可选地在临时的完全脱离 hardlink 的副本中运行
  Makefile；默认不执行任意题目服务或 Docker，以保持批量生成稳定并避免污染种子。

## 快速开始

项目使用 `mise` 固定工具链、使用 `uv` 管理环境和 Python 命令。在 `MyBench/` 目录执行：

```bash
mise install
mise run install

mise run discover
mise run pipeline
```

等价的 `uv` 命令是：

```bash
uv sync
uv run mybench discover --ctfbench ../CTFbench --split all --category pwn rev
uv run mybench pipeline \
  --ctfbench ../CTFbench \
  --split all \
  --category pwn rev \
  --output ./generated \
  --variants-per-seed 1 \
  --clean
```

成功后可以查看：

- `MyBench/generated/catalog.json`：发现到的 seed、变体数量和相对路径；
- `MyBench/generated/validation_report.json`：每个实例的检查结果；
- `MyBench/generated/variants/<category>/<split>/<variant>/mutation_manifest.json`：
  单个变体的父题、操作、哈希、entrypoint、构建提示和可复现种子；
- 每个变体目录中的 `MUTATION.md`、`run_variant.sh`（若发现安全入口）或
  `variant_runtime.json`（没有安全入口时）。

当前仓库中 `mise run pipeline` 的全量结果是 110 个变体（pwn 49、rev 61），
验证 110/110 通过。其中 80 个变体发生了部署制品级变异（`compiled_artifact_rebuild`
26 个、`binary_cfg_mutation` 54 个），35 个变体有已检查的源码级 guard；两者可以重叠。
剩余 21 个变体被明确记录为跳过，原因是 seed 只有不可自动重建的脚本/模块/压缩内容，
或原生入口没有可安全改写且能证明 CFG 变化的指令。它们不会被统计成已完成的实质变异，
需要后续增加对应语言/二进制格式的专用变异器。

## 命令

```bash
# 只枚举题目
uv run mybench discover --ctfbench ../CTFbench --split development --category pwn rev

# 生成变体，不验证
uv run mybench generate --ctfbench ../CTFbench --output ./generated \
  --variants-per-seed 2 --clean

# 验证已有生成目录
uv run mybench validate --input ./generated

# 验证并在存在 Makefile 时尝试构建；构建失败会记录为 warning，题目仍会保留
uv run mybench validate --input ./generated --build
```

## 变异契约和后续扩展

当前雏形的稳定契约是“题目目录和声明文件保持可用、满足前置条件的源码和实际部署
artifact 发生确定性变异、秘密不进入公共 metadata、所有操作可由 manifest 重放”。源码
变异、artifact 重建、运行时入口操作和明确跳过的源码变异分开记录，后续可以在同一接口下添加：

- C/C++ 的局部变量/结构体布局、编译保护、协议 wrapper；
- pwn 的堆分配序列、格式串栈噪声、PIE/Canary/RELRO 组合；
- rev 的常量拆分、状态机、字符串运行时解密和间接调用；
- Docker/compose 沙箱中的参考 solver 重放和隐藏 oracle；
- CFG/字符串相似度去重、ASLR 多轮验证和 fuzz/coverage witness。

这些增强应继续遵守 `mutation_manifest.json` 的 provenance 和后置验证接口，而不要
为不同题型添加人工维护的单题脚本。
