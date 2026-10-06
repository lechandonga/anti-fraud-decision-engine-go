# Anti-Fraud Decision Engine (Go, 本地可运行)

一套完全本地、零外部依赖的反欺诈风险判定与告警服务。用本地交易事件与名单/规则数据模拟风控场景，保证并发接入、规则在线变更与告警处置之后的判定结论与状态**可预期、可追溯、可复现**。

## 快速开始

```bash
go test ./... -v          # 运行全部单测（日志含业务场景与用例说明）
go run ./cmd/server       # 启动本地 HTTP 服务，默认 :8080，可用 ADDR=:18099 覆盖
```

示例：

```bash
# 上报事件
curl -XPOST localhost:8080/events -d '{"event_id":"e1","account_id":"acc-blacklisted","amount":100,"currency":"CNY","occurred_at":"2026-10-06T12:00:00Z"}'
# 发布新规则版本（原子生效）
curl -XPUT localhost:8080/rules -d '{"version":"v2","rules":[{"id":"high-amount","type":"amount_threshold","threshold":500000,"score":50}]}'
# 回放历史事件到指定版本
curl -XPOST localhost:8080/replay/v1
# 处置告警（幂等）
curl -XPOST localhost:8080/alerts/AL-000001/actions -d '{"action":"resolve","actor":"op-1","request_id":"req-1"}'
```

## 规则模型

规则集合 `RuleSet` 以 `version` 标识、整体发布、不可变；单条规则 `Rule`：

| 类型 | 语义 | 关键字段 |
|---|---|---|
| `amount_threshold` | 单笔金额 ≥ 阈值即命中 | `threshold`（最小货币单位，如分） |
| `frequency` | 同账户在 `window` 内（按 `occurred_at`）事件数 ≥ `count` | `window`、`count` |
| `blacklist` | 指定字段命中名单 | `field`（`account_id`/`merchant_id`/`ip`）、`values` |

每条规则带 `score`；事件得分为所有命中规则分数之和。风险等级：`score >= 80` 为 `HIGH`，`>= 40` 为 `MEDIUM`，否则 `LOW`。金额使用整数（最小货币单位），避免浮点歧义。

## 判定语义

- **并发接入**：`Ingest` 内部串行化，任意并发调用结果确定；频次窗口按事件的 `occurred_at` 计算，乱序到达不影响计数正确性。
- **幂等去重**：同一 `event_id` 只被计分一次；重复提交返回 `DUPLICATE_EVENT` 拒绝，不产生重复告警。
- **拒绝原因可区分**：缺关键字段 `MISSING_FIELD`、金额非法 `INVALID_AMOUNT`、时间戳异常（零值/超过 24h 前/超过 5 分钟未来）`INVALID_TIMESTAMP`。坏事件被记录且绝不阻塞或污染后续判定。
- **可解释**：每条决策包含命中明细 `hits[]`（规则 ID、命中原因、分数）。

## 规则版本与可复现性

- 规则更新**原子生效**：单次判定只使用一个版本的快照，绝不混用新旧规则。
- 每条决策记录 `rule_version`，决策一旦写入即不可变。
- `Replay(version)` 按原始接入顺序用指定版本重放，同版本重放结果与历史决策完全一致（`VerifyReplay` 校验）。
- `Rollback(version)` 只影响后续判定，历史决策不变；所有已发布版本永久保留可回放。

## 告警语义

- 同一事件命中同一规则只产生一条告警（按 `(event_id, rule_id)` 去重）。
- 状态机：`OPEN → ACKNOWLEDGED → RESOLVED`，`OPEN → RESOLVED` 亦合法；`RESOLVED` 为终态。每次流转都记录审计历史（操作人、request_id、时间）。
- 处置结果三态：`APPLIED`（本次生效）、`DUPLICATE_REQUEST`（同一 `request_id` 重复提交，幂等返回当前状态）、`CONFLICT`（状态已被其他请求推进，本次流转非法）。并发处置同一条告警时只有一个请求生效。

## HTTP 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/events` | 接入事件，返回决策或拒绝原因 |
| GET | `/decisions/{eventID}` | 查询事件的不可变决策 |
| GET/PUT | `/rules` | 查看当前规则 / 原子发布新版本 |
| POST | `/rules/rollback/{version}` | 回滚到历史版本 |
| POST | `/replay/{version}` | 用指定版本重放全部已接受事件 |
| GET | `/alerts` | 告警列表 |
| POST | `/alerts/{id}/actions` | 幂等处置（`action`/`actor`/`request_id`） |

## 版本兼容范围

- 规则 JSON 模型向后兼容：旧版本规则集永远可回放；新增规则类型会拒绝未知 `type` 而不是静默忽略。
- 决策与告警为只追加（append-only）语义，已产生的历史记录在任何规则变更/回滚下保持不变。
- 拒绝原因、处置结果枚举为稳定契约，新增取值只会追加不会修改既有含义。

## 本地验证

```bash
go vet ./...
go test ./... -v                 # 业务覆盖日志：并发接入 / 重复乱序 / 畸形事件 / 规则变更回放 / 告警并发处置
CGO_ENABLED=1 go test ./... -race  # 竞态检测
```

测试覆盖：`TestConcurrentIngestion`（并发接入与频次计数）、`TestDuplicateAndOutOfOrderEvents`（重复去重、乱序计数、告警去重）、`TestMalformedEvents`（8 类畸形事件的可区分拒绝与隔离性）、`TestRuleUpdateAtomicityAndReplay`（并发规则变更下的版本一致性、回放一致、回滚不改历史）、`TestAlertLifecycleAndConcurrentHandling`（合法流转审计、幂等重放、并发处置唯一生效）。
