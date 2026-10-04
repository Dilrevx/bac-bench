# BAC case contract v1

这是 BAC-Bench 的规范化数据层，不是 MPC 的权限审核契约，也不是完整池评测 manifest。
不同 benchmark 的组织方式一致，但不伪造相同的审核或运行状态。

## 身份和原记录

- `schema_version = bac.case.v1`。
- `record_id = bac-bench::<upstream id>`，`source_record_id` 保留作者原 ID，`source = absentia`。
- `repository_url` 保留目标项目地址；`language`、`framework` 保留原始值。
- `revisions.checkout` 是作者标出的漏洞 commit，`checkout_kind = vulnerable_commit`；
  `revisions.fix` 是作者标出的修复 commit。均保存完整 SHA，不从版本号猜提交。
- `vulnerability_ids` 保存 advisory URL 中的大写 GHSA 身份，不把多个入口当多个 advisory。
- `raw_ref.path` 指向原文件 `data/authz_instances.jsonl`，`jsonl_line` 为实际 1-based 行号，
  `record_sha256` 是原 JSON 对象的 canonical 哈希。

同一案例的多个行段不增加案例数，不同 advisory 可以共享同一目标代码快照。
案例、仓库、漏洞快照、修复快照和 sink 行段分别计数；跨 benchmark 重叠不自动消失。

## 来源和审核

`provenance` 保存原作者仓库、固定上游提交及 `author_reported_human_validation`。
它是来源声明，不是我们重新完成的静态审查。
初始导入明确使用：

```json
{
  "review": {"local_status": "pending_review"},
  "runtime_status": "not_run",
  "training_status": "not_assessed",
  "pool_status": "not_built"
}
```

规范化和哈希校验不会把这些状态提升为 `static_source_review`、训练就绪或运行确认。
后续提升状态需另有可追溯审核/执行证据及对应的协议版本，不直接重写原始数据。

## 评分侧信息

`evaluator_only` 保留原始 `advisory_url`、`fix_url`、`affected_routes`、`invariant`、`violation`、
`root_files`、`root_symbols`、`sink_files`、`sink_locations`、`expected_cwes`、
`expected_categories`、`payload_types`、`match_keywords`、`match_criteria`。
原始新增未知字段也保留在评分侧，不因列名未知就进入模型输入。
修复 SHA 在 `revisions` 中用于版本溯源，仍不进入漏洞版 guideline-only 的模型请求。

模型使用冻结的类别级 guideline 和目标项目源码；不能把原 ID/GHSA、官方位置、修复 diff、
逐案例 invariant 或匹配关键词当作查询。源码下载元数据可以给 `repository_url` 和漏洞 SHA，
但这不是漏洞语义查询。身份映射留在可信实验控制端。

paired credit 只要求相应已知缺陷在漏洞版本被发现、修复版本不再被报；
它不证明修复版本整仓安全，也不自动把其他 finding 判成误报。

## 可复核的派生文件

原 `data/` 文件与固定上游 Git 对象保持一致。`source.json` 保存原始 JSONL 与规范 cases 文件的
SHA-256/字节数、canonical 原记录哈希、规范化版本与分别计数。
canonical 原记录表示为 `json.dumps(ensure_ascii=False, sort_keys=True, indent=2)` 加一个换行的 UTF-8 字节。
规范 cases 按原非空记录顺序，每行使用 sort-keys、compact separators 的 UTF-8 JSON，加换行。

`generate` 只写缺失或字节相同的派生文件，拒绝覆盖不一致的已有内容；`validate` 重新计算并比对全部派生字节。
embed 锁定本 fork 的适配提交及相关文件哈希，不执行 benchmark 仓库中的任何工具来加载数据。
