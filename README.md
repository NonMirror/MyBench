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

### 分析干扰策略

源码变异默认加入四类与题目逻辑无关的分析干扰：`decoy_function_injection` 生成未被
调用的无害函数，`dead_code_injection` 生成确定为假的局部路径，
`duplicate_string_injection` 保留重复字符串常量，`irrelevant_syscall_injection` 在
不可达 guard 内保留只读 `getpid` 调用。每个操作都记录策略、语言、marker 以及前后
SHA-256；不支持的语言会记录 skipped，绝不会把注释或元数据当成变异。

策略写入每个 `mutation_manifest.json`，并明确排除控制流平坦化、OLLVM 家族、packing
和 shell loader。机器可读示例见 [`noise_policy.example.json`](noise_policy.example.json)
和 [`noise_policy.schema.json`](noise_policy.schema.json)。可通过完整示例或内嵌
`noise_policy` 对象传给 `generate`/`pipeline`：

```bash
uv run mybench pipeline --ctfbench ../CTFbench --output ./generated \
  --category pwn rev --noise-policy ./noise_policy.example.json --clean
```

将某个 `limits` 项设为 `0` 会保留该 operator 的 skipped provenance。生成器只使用
普通源码级构造，不实现控制流平坦化、虚拟化、加壳或壳加载器。

### 当前手法与样本覆盖

下面的“生效”表示对应 operation 的 `changed: true`，并且变体中的实际源码或二进制
经过了后置校验。样本名使用数据集的 `parent_id`；具体修改文件在该样本的
`mutation_manifest.json` 中由 `path` 给出。

| operation | 实现条件 | 本次全量运行中生效的样本 |
| --- | --- | --- |
| `opaque_guard_injection` | 发现可解析的 C/C++、Go、Python 或 JS/TS 函数；guard 使用确定性 false 条件和 `volatile`，不改变正常输出。 | 25 个：`2014f-pwn-kernel`、`2016q-pwn-hungman`、`2016q-rev-rock`、`2017q-pwn-pilot`、`2017q-rev-prophecy`、`2017q-rev-realism`、`2017q-rev-tablez`、`2018f-rev-free_as_in_freedom`、`2018q-pwn-bigboy`、`2018q-pwn-shellpointcode`、`2018q-rev-a_walk_through_x86_part_1`、`2019q-rev-beleaf`、`2020q-pwn-thebardsfail`、`2020q-rev-baby_mult`、`2020q-rev-ezbreezy`、`2021q-pwn-haystack`、`2021q-pwn-krypto`、`2021q-rev-checker`、`2022q-rev-the_big_bang`、`2023q-pwn-my_first_pwnie`、`2023q-pwn-puffin`、`2023q-pwn-target_practice`、`2023q-rev-baby_s_first`、`2023q-rev-baby_s_third`、`2023q-rev-whataxor`。 |
| `decoy_function_injection` | 只对 C/C++ 注入未调用的 `noinline`/`used` 辅助函数。 | 与另外三类源码干扰相同的 18 个：`2014f-pwn-kernel`、`2016q-pwn-hungman`、`2016q-rev-rock`、`2017q-pwn-pilot`、`2017q-rev-prophecy`、`2017q-rev-tablez`、`2018q-pwn-bigboy`、`2018q-pwn-shellpointcode`、`2019q-rev-beleaf`、`2020q-pwn-thebardsfail`、`2020q-rev-baby_mult`、`2020q-rev-ezbreezy`、`2021q-pwn-haystack`、`2021q-pwn-krypto`、`2023q-pwn-puffin`、`2023q-pwn-target_practice`、`2023q-rev-baby_s_third`、`2023q-rev-whataxor`。 |
| `dead_code_injection` | 只对 C/C++ 注入由 `volatile` 计算保护的确定性 false 局部路径。 | 上述 18 个样本。 |
| `duplicate_string_injection` | 只对 C/C++ 保留两份 `volatile` 重复字符串，并通过无关 helper 保持二进制可见。 | 上述 18 个样本。 |
| `irrelevant_syscall_injection` | 只对 C/C++ 注入不可达 guard 内的只读 `getpid` 调用；结果不参与题目逻辑。 | 上述 18 个样本。 |
| `compiled_artifact_rebuild` | 源文件为 C/C++，且存在同 basename 的已部署可执行文件；编译后格式、架构、哈希和 CFG witness 都必须匹配/变化。 | 16 个：`2016q-pwn-hungman`、`2016q-rev-rock`、`2017q-pwn-pilot`、`2017q-rev-prophecy`、`2017q-rev-tablez`、`2018q-pwn-bigboy`、`2018q-pwn-shellpointcode`、`2019q-rev-beleaf`、`2020q-pwn-thebardsfail`、`2020q-rev-baby_mult`、`2020q-rev-ezbreezy`、`2021q-pwn-haystack`、`2023q-pwn-puffin`、`2023q-pwn-target_practice`、`2023q-rev-baby_s_third`、`2023q-rev-whataxor`。 |
| `binary_cfg_mutation` | 没有可用源码重建时，目标必须是 ELF/Mach-O/PE，radare2 能分析用户函数，并找到可保持指令长度的 x86/AArch64 条件跳转。 | 63 个；包括 `2013q-pwn-csaw_diary`、`2014q-pwn-ish`、`2014q-rev-aerosol_can`、`2015f-pwn-hipster`、`2015f-rev-wyvern2`、`2015q-pwn-meme_shop`、`2015q-rev-ftp`、`2015q-rev-wyvern`、`2016f-pwn-detective`、`2016f-rev-palo_alto`、`2016q-pwn-tutorial`、`2016q-pwn-warmup`、`2016q-rev-deedeedee`、`2017f-pwn-humm_sch_t`、`2017f-rev-48_bit_yeet_lab`、`2017f-rev-rabbithole`、`2017q-pwn-zone`、`2017q-rev-bananascript`、`2017q-rev-gopherz`、`2017q-rev-grumpcheck`、`2018f-pwn-es1337`、`2018f-rev-1nsayne`、`2018q-pwn-get_it`、`2018q-rev-kvm`、`2019f-pwn-arevenge`、`2019f-rev-steady_counting`、`2019f-rev-wrangly`、`2019q-pwn-baby_boi`、`2019q-pwn-got_milk`、`2019q-pwn-pop_goes_the_printer`、`2019q-pwn-popping_caps`、`2019q-pwn-popping_caps_2`、`2019q-pwn-traveller`、`2019q-rev-call_site`、`2019q-rev-gibberish_check`、`2019q-rev-wizkid`、`2020f-rev-brrr`、`2020f-rev-rap`、`2020f-rev-yeet`、`2020q-pwn-blox2`、`2020q-pwn-feather`、`2020q-pwn-grid`、`2020q-pwn-roppity`、`2020q-rev-not_malware`、`2021f-pwn-chatterbox`、`2021f-pwn-horrorscope`、`2021f-rev-maze`、`2021q-pwn-alien_math`、`2021q-pwn-password_checker`、`2021q-rev-ransomware`、`2022f-pwn-salt_server`、`2022f-rev-parallel_vm`、`2022q-pwn-unsafe_linking`、`2022q-rev-game`、`2023f-rev-unvirtualization`、`2023f-rev-virtualization`、`2023q-pwn-unlimited_subway`、`2023q-rev-rebug_1`、`2023q-rev-rebug_2`、`2023q-rev-rox`；完整清单以 manifest 为准。 |

`runtime_entrypoint_wrapper`（96 个）和 `runtime_metadata_overlay`（14 个）是运行时
打包降级，不属于 pwn/rev 实质变异：前者只是把原入口放到 `run_variant.sh` 并设置
变体环境变量，后者只写入 `variant_runtime.json`。它们不能替代源码或二进制变异。

### 为什么其它样本被跳过

跳过是按前置条件逐项记录的，不会把失败编译、未知格式或没有可证明 CFG 变化的情况
伪装成成功。当前全量运行的原因如下：

- 四类源码分析干扰各有 69 个 skipped。11 个是语言/文件类型不在 C/C++ 注入器范围：
  `.py` 的 `2017q-rev-realism`、`2018f-rev-free_as_in_freedom`、
  `2018q-rev-a_walk_through_x86_part_1`、`2021q-rev-checker`、`2022q-rev-the_big_bang`、
  `2023q-pwn-my_first_pwnie`、`2023q-rev-baby_s_first`；`.rs` 的
  `2017f-rev-rusty_road`、`2020f-rev-yeet`；`.h` 的 `2019q-pwn-pop_goes_the_printer`；
  `.java` 的 `2022f-rev-roulette`。其余 58 个虽然发现了可处理的源码，但兼容的部署
  artifact 重建失败，生成器因此恢复原源码，避免“源码变了、实际运行文件没变”。这
  58 个按 manifest 的底层原因分为：33 个没有同 basename 可执行文件，10 个源码重建
  本身不支持（Python 7、Go 3），8 个旧 API/隐式声明被编译器拒绝，1 个架构/格式不匹配，
  1 个 C++17 要求，1 个 `_start` 链接冲突，1 个普通编译失败，1 个依赖链接失败，
  1 个缺少 KVM guest 对象，1 个内联汇编不兼容。
- `opaque_guard_injection` 的其它样本是 23 个没有候选源码的预编译题、上述 58 个因
  部署 artifact 重建失败而恢复源码的样本，以及 `.h`/`.rs`/`.java` 文件；没有函数
  定义可安全插入时只记录 `source_mutation_skipped`。

其中 23 个没有候选源码的样本是：`2013q-pwn-csaw_diary`、`2014f-rev-odd`、
`2014f-rev-return_of_the_weiner`、`2014q-pwn-ish`、`2014q-rev-aerosol_can`、
`2014q-rev-weissman`、`2015f-pwn-hipster`、`2015f-rev-wyvern2`、
`2015q-rev-ftp`、`2015q-rev-wyvern`、`2016f-rev-palo_alto`、`2016q-rev-deedeedee`、
`2017f-pwn-humm_sch_t`、`2017q-rev-bananascript`、`2018f-rev-1nsayne`、
`2018q-rev-a_walk_through_x86_part_2`、`2019f-rev-steady_counting`、
`2019q-rev-wizkid`、`2020f-rev-sourcery`、`2020q-pwn-blox2`、`2020q-pwn-pwnvoltex`、
`2022q-rev-dockreleakage`、`2023f-rev-unvirtualization`。这些题目只有预编译入口、
数据或非候选源码，生成器无法证明源码注入会进入实际运行路径。
- `compiled_artifact_rebuild` 的 67 个 skipped 中，35 个没有与源码同 basename 的已部署
  可执行文件，不能证明源码会进入运行路径；17 个是 Go/Python 等不在自动 C/C++ 重建
  范围内（`.py` 14 个、`.go` 3 个）；其余 15 个因编译器/链接器、架构或语言标准
  不兼容而失败（例如 32 位共享对象与本机 64 位输出不匹配、`gets`/`setgroups` 等
  旧 API、手写 `_start`、缺少 KVM 依赖、C++17 要求或内联汇编不兼容）。这些题目不会
  留下 source-only 变体。
- `binary_cfg_mutation` 的 22 个 skipped 中，18 个入口不是支持的原生 ELF/Mach-O/PE，
  2 个没有可保持长度的条件跳转（`2019q-pwn-small_boi`、`2022q-rev-anyagacha`），
  2 个 radare2 无法分析 `main`/`entry0`（`2014f-rev-odd`、`2021q-rev-macomal`）。
  wrapper 本身从不作为 CFG 变异目标。

为便于复核，二进制路径中 18 个非原生入口是：
`2017q-rev-realism`、`2018f-rev-free_as_in_freedom`、
`2018q-rev-a_walk_through_x86_part_1`、`2018q-rev-a_walk_through_x86_part_2`、
`2019f-rev-mystery_boi`、`2020f-pwn-darkunion1`、`2020q-pwn-slithery`、
`2021f-rev-sfc`、`2021q-pwn-krypto`、`2021q-rev-checker`、
`2021q-rev-ncore`、`2022f-pwn-cryptopwn`、`2022q-pwn-ezrop`、
`2022q-rev-the_big_bang`、`2023f-pwn-brainflop`、`2023f-rev-cell`、
`2023q-pwn-my_first_pwnie`、`2023q-rev-baby_s_first`。它们的入口是脚本、数据、
压缩内容或其它非原生载荷，不能安全套用原生指令补丁。

源码干扰因“重建失败后恢复源码”而跳过的 58 个样本为：
`2014q-pwn-the_road_less_traveled`、`2015q-pwn-meme_shop`、`2016f-pwn-detective`、
`2016q-pwn-tutorial`、`2016q-pwn-warmup`、`2017f-rev-48_bit_yeet_lab`、
`2017f-rev-rabbithole`、`2017q-pwn-zone`、`2017q-rev-gopherz`、
`2017q-rev-grumpcheck`、`2018f-pwn-es1337`、`2018f-rev-bdos`、`2018q-pwn-get_it`、
`2018q-rev-kvm`、`2019f-pwn-arevenge`、`2019f-rev-mystery_boi`、`2019f-rev-wrangly`、
`2019q-pwn-baby_boi`、`2019q-pwn-got_milk`、`2019q-pwn-popping_caps`、
`2019q-pwn-popping_caps_2`、`2019q-pwn-small_boi`、`2019q-pwn-traveller`、
`2019q-rev-call_site`、`2019q-rev-gibberish_check`、`2019q-rev-halfpike`、
`2020f-pwn-darkunion1`、`2020f-rev-brrr`、`2020f-rev-rap`、`2020q-pwn-feather`、
`2020q-pwn-grid`、`2020q-pwn-roppity`、`2020q-rev-not_malware`、
`2021f-pwn-chatterbox`、`2021f-pwn-horrorscope`、`2021f-rev-maze`、
`2021f-rev-sfc`、`2021q-pwn-alien_math`、`2021q-pwn-password_checker`、
`2021q-rev-macomal`、`2021q-rev-ncore`、`2021q-rev-ransomware`、
`2022f-pwn-cryptopwn`、`2022f-pwn-salt_server`、`2022f-rev-parallel_vm`、
`2022q-pwn-ezrop`、`2022q-pwn-unsafe_linking`、`2022q-rev-anyagacha`、
`2022q-rev-game`、`2023f-pwn-brainflop`、`2023f-pwn-virtualization_pwn`、
`2023f-rev-cell`、`2023f-rev-virtualization`、`2023q-pwn-unlimited_subway`、
`2023q-rev-rebug_1`、`2023q-rev-rebug_2`、`2023q-rev-rox`。具体编译器输出、格式
不匹配或缺少依赖的细节保存在各自 manifest 的 `reason` 字段中。

因此，“跳过”表示当前实现无法同时证明语义保持、实际运行路径和变异可验证性；要覆盖
这些样本，需要增加对应语言的源码注入器、目标工具链/交叉编译器，或针对其二进制格式
的专用分析器，而不是放宽现有校验。

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
  --noise-policy ./noise_policy.example.json \
  --clean
```

成功后可以查看：

- `MyBench/generated/catalog.json`：发现到的 seed、变体数量和相对路径；
- `MyBench/generated/validation_report.json`：每个实例的检查结果；
- `MyBench/generated/variants/<category>/<split>/<variant>/mutation_manifest.json`：
  单个变体的父题、操作、哈希、entrypoint、构建提示和可复现种子；
- 每个变体目录中的 `MUTATION.md`、`run_variant.sh`（若发现安全入口）或
  `variant_runtime.json`（没有安全入口时）。

基于当前仓库的全量运行（pwn 49、rev 61，共 110 个变体），验证结果为 110/110
通过；其中 79 个变体发生了部署制品级变异（`compiled_artifact_rebuild` 16 个、
`binary_cfg_mutation` 63 个），25 个变体完成了 `opaque_guard_injection`，18 个变体
完成了四类源码分析干扰。源码干扰和部署制品变异可以重叠；skipped 只表示对应操作的
前置条件不满足，不表示变体验证失败。下面的样本清单来自同一批
`mutation_manifest.json`，重新生成数据集后应以 manifest 中的实际清单为准。

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
