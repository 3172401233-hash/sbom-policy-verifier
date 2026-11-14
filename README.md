# sbom-policy-verifier

纯 Python、零第三方依赖的离线 SBOM 策略验证器，输入 [CycloneDX](https://cyclonedx.org/)
JSON 文档和一份策略 JSON，输出命中的策略规则、从根组件出发的直接依赖路径以及例外
是否仍然有效。所有解析与比较均在本地完成，不发起任何网络请求。

## 解决的问题

门禁里常见的文本名称比对有两个绕过面：

- **同名不同版本**：仅按 `name` 命中会把所有版本一起放过或一起拦截；本库优先使用
  规范化后的 [purl](https://github.com/package-url/purl-spec) 坐标（type / namespace /
  name）识别组件，版本交给独立的范围规则判断。
- **改名包**：组件改名后文本名称不再匹配，但 purl 坐标不变，基于 purl 的规则依然命中。

## 身份规范化

- **purl**：本地解析并规范化大小写、URL 编码、qualifier 排序、subpath，生成 canonical
  字符串；purl 默认忽略版本比较坐标，支持 `compare_version=True` 精确到版本。
- **name**：trim、合并空白、转小写。
- **version**：trim 并合并内部空白；比较时按数字/字母 token 解析，支持 SemVer 风格的
  预发布排序（`1.0.0-alpha < 1.0.0`）。
- **supplier**：接受字符串或 CycloneDX 对象（优先 `name`，回退 `url`），统一小写比较。
- **licenses**：解析 `license.id`、`license.name` 与 SPDX 表达式
  （`MIT OR GPL-3.0-only`、`(A AND B) WITH ...`），拆分为大写 SPDX 标识集合。

## 依赖图

按 `dependencies[].dependsOn` 构建有向图，检测结果通过结构错误上报，绝不静默忽略：

| 错误码 | 触发条件 |
| --- | --- |
| `duplicate_bom_ref` | 多个组件（或与 `metadata.component`）使用相同 `bom-ref` |
| `dangling_reference` | `ref` 或 `dependsOn` 指向不存在的 `bom-ref` |
| `dependency_cycle` | 依赖边构成环，报告环上的完整引用链 |
| `unknown_identity` | 组件既没有可用 purl 也没有 name |
| `invalid_purl` | purl 字段无法解析 |
| `invalid_component` / `invalid_dependency` | 条目不是对象或缺少 `ref` |
| `unsupported_format` | `bomFormat` 不是 `CycloneDX` |

每个命中的策略都会附带一条从根组件（未被任何 `dependsOn` 引用的组件）到目标组件的
最短依赖路径（BFS，环安全）。

## 策略字段

策略 JSON 顶层包含 `rules` 和 `exceptions` 两个数组。

### `rules[]`

| 字段 | 适用类型 | 说明 |
| --- | --- | --- |
| `id` | 全部 | 规则唯一标识，例外通过 `rule_id` 关联 |
| `type` | 全部 | 见下表四种规则类型 |
| `purl` | 全部 | 可选选择器；按 type/namespace/name 坐标匹配，忽略版本 |
| `name` | 全部 | 可选选择器；规范化后的精确名称匹配 |
| `version_range` | `deny_version` / `deny_component` | 版本约束，支持 `==` `!=` `>` `>=` `<` `<=`，逗号表示 AND，数组元素表示 OR；裸版本号视为精确匹配 |
| `licenses` | `deny_license` | SPDX 标识列表，命中组件任一许可证即触发 |
| `message` | 全部 | 可选，覆盖结果中的默认描述 |

同一规则上同时给出多个选择器时按逻辑 AND 组合。

| `type` | 命中条件 |
| --- | --- |
| `deny_component` | 选择器（purl / name，可选 `version_range`）匹配的组件 |
| `deny_version` | 选择器匹配且组件版本落在 `version_range` 内 |
| `deny_license` | 组件许可证集合与 `licenses` 有交集（自动拆分 SPDX 表达式） |
| `deny_missing_supplier` | 组件缺少规范化后的 supplier；可再用 purl/name 缩小范围 |

### `exceptions[]`

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `id` | 是 | 例外唯一标识 |
| `rule_id` | 是 | 必须引用一条已存在的规则，否则策略加载失败 |
| `purl` / `name` | 否 | 组件选择器，语义与规则相同，用于限定例外适用的组件 |
| `reason` | 否 | 例外理由，会原样写入报告 |
| `expires_at` | 是 | ISO 8601 到期时间（`Z` 后缀按 UTC 处理）；缺失时例外状态为 `missing_expiry`，不豁免任何命中 |

例外状态：`active`（当前时间早于到期时间，命中被豁免）、`expired`（已到期，仍显示在
报告中但不再豁免）、`missing_expiry`（缺少到期时间，视为无效）。

## 用法

```bash
# 文本摘要，退出码 0=通过，1=存在违规，2=输入错误
python -m sbom_policy_verifier examples/sbom.json examples/policy.json

# 完整 JSON 报告
python -m sbom_policy_verifier examples/sbom.json examples/policy.json --json
```

作为库调用：

```python
from sbom_policy_verifier import verify

report = verify("path/to/sbom.json", "path/to/policy.json")
print(report.passed)                 # 结构错误与未豁免违规均为空
for finding in report.violations:    # 未被例外覆盖的命中
    print(finding.rule_id, finding.component, finding.dependency_path)
for finding in report.exempted:      # 仍在有效期内的例外命中
    print(finding.exception.expires_at)
```

示例输入位于 `examples/`。

## 测试

测试通过辅助工厂生成多个 CycloneDX SBOM，覆盖传递依赖路径、同名不同版本、许可证
表达式组合、有效/过期/缺少到期时间的例外、改名包、依赖环、悬空引用、重复 `bom-ref`
和未知身份：

```bash
python -m unittest
```
