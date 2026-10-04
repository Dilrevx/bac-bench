# BAC-Bench — embed 数据适配

本仓库是 [avduarte333/Absentia](https://github.com/avduarte333/Absentia) 的 fork，
为 [Dilrevx/embed](https://github.com/Dilrevx/embed) 保存 BAC-Bench 的规范化案例和版本溯源。
BAC-Bench 由 ABSENTIA 作者发布；本仓库不冒称原 benchmark 或检测方法的作者。

## 数据与目录

原始数据固定于上游提交 `80e30361ebe3d6a779886ecb42a8ecbe7e75a561`，
包含 30 条公开授权漏洞 advisory、25 个项目、30 个漏洞快照和 30 个修复快照。
87 个 sink 行段是定位标签，不是 87 个独立漏洞。完整应用源码仍在各自上游项目。

| 位置 | 内容 |
|---|---|
| [data/](data/README.md) | 作者原始 JSONL、CSV 和数据说明，保留字节，不重写标签 |
| [cases.jsonl](datasets/bac-bench/cases.jsonl) | 带来源限定身份、版本与原记录引用的规范化案例 |
| [source.json](datasets/bac-bench/source.json) | 上游提交、原文件与派生文件哈希、逐记录哈希 |
| [summary.json](datasets/bac-bench/summary.json) | 案例、仓库、快照与行段的分别计数 |
| [tools/normalize.py](tools/normalize.py) | 确定性生成与一致性校验 |
| [数据合同](docs/DATA_CONTRACT.md) | 规范字段、评分信息与准入状态 |

方法实现、训练、模型评估和实验结果放在 embed，不在本仓库复制维护。
embed 应锁定**本仓库生成规范化数据后的固定提交**；上游提交单独留作 provenance。
本仓库不并入 MPC，不复用 MPC 的本地审核标签或实验分母。

## 校验

Python 3.9+、Git、标准库即可，不执行目标应用：

```sh
python3 tools/normalize.py generate
python3 tools/normalize.py validate
python3 -m unittest discover -s tests -v
```

派生文件由原始 JSONL 确定性生成。内容相同则不改文件，已有内容不一致时拒绝覆盖；
验证会核对原始文件与固定 Git 对象、规范记录、原记录引用、哈希及计数。

## 当前边界

30 例保留作者报告的人工核验来源；这不等于我们已逐例复核或运行复现。
初始规范记录为本地 `pending_review`、运行 `not_run`、训练 `not_assessed`、候选池 `not_built`。
这些状态不改变作者原始标签，也不把未审核或未命中的位置当作负例。

advisory、invariant、violation、修复信息、路由/符号/位置和匹配规则只用于评分与溯源，
不用于构造 guideline-only 的逐案例查询。修复版本只对相应已知缺陷提供对照，不代表全仓无漏洞。
原 benchmark 是源码检测；位置命中不是动态确认，其他新 findings 需独立审核。
与既有训练/开发数据的重叠、全仓候选池和正式评估协议仍需在实际实验前准备。

来源与许可边界见 [DATA_LICENSES.md](DATA_LICENSES.md)。
