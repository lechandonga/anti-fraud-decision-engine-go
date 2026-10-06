# 本地反欺诈风险判定与告警服务

纯内存、零外部依赖的反欺诈风控服务：本地交易事件 + 版本化规则/名单，
提供并发事件判定、规则在线变更与历史回放、告警生命周期与幂等处置。

## 快速开始

```bash
go run ./cmd/server            # 默认监听 :8080，可用 ADDR=:9000 覆盖
go test ./...                  # 运行全部自动化测试
go test -race -v ./...         # 竞态检测 + 查看业务覆盖日志
```

启动时自动发布演示规则集 `v1`（大额、5 分钟频次、黑白名单）。

## 规则模型

规则与名单打包在同一个不可变快照 `RuleSet` 中，通过整包原子替换生效：

| 维度 | 规则字段 | 命中条件 |
| --- | --- | --- |
| 金额 `amount` | `min_amount` | `amount >= min_amount` |
| 频次 `frequency` | `window_ns`、`threshold` | 以事件发生时间为中心，窗口内同账户事件数（含当前）`>= threshold` |
| 名单 `list` | `list_type=black|white`、`match_on=[account,counterparty]` | 字段值在对应类型名单内 |

- 风险等级：`LOW < MEDIUM < HIGH < CRITICAL`，结论取所有命中中的最高等级；
  无命中为 `PASS`。
- 白名单优先：账户或交易对手命中白名单时直接豁免（`exempted=true`、`PASS`），
  不再评估金额/频次/黑名单。
- 频次以**事件时间**（`occurred_at`）窗口计数，而非处理墙钟时间，
  因此乱序接入、历史重放都能得到确定结论。
- 每个规则集带 `schema_version` 与内容哈希（SHA-256 截断），
  决策记录固定引用 `ruleset_version` 与 `ruleset_hash`。

## 判定语义

- `event_id` 是全局幂等键：同一事件并发、重复或乱序到达只接受一次，
  后续提交返回 `DUPLICATE` 和首次结论，不重复计分、不重复告警。
- 每条接受事件分配单调递增 `seq`；判定基于此前已接受事件的固定快照，
  结论只取决于接入顺序，与并发调度无关。
- 畸形事件不会被静默丢弃：返回 `REJECTED` + 可区分原因码，不参与计分、
  不产生告警，也不阻塞后续事件。原因码：
  `MISSING_EVENT_ID`、`MISSING_ACCOUNT_ID`、`MISSING_CURRENCY`、
  `UNSUPPORTED_CURRENCY`、`INVALID_AMOUNT`、`MISSING_TIMESTAMP`、
  `TIMESTAMP_IN_FUTURE`、`TIMESTAMP_TOO_OLD`
  （未来偏移、历史窗口、币种在 `engine.Config` 中可配置）。
- 带 `event_id` 的坏事件重复提交同样判重，并可追溯首次拒绝原因。

## 版本与回放

- 发布新版本：校验通过后原子切换当前版本；版本号唯一、不可覆盖。
- 进行中的判定持有旧快照指针，规则变更绝不与新规则混用。
- `Replay(version, events)` 只读重放：同版本 + 同事件序列必然产生
  逐字段一致的结论（风险等级、命中明细、规则哈希）。
- 回滚只是把当前指针切回历史快照，只影响之后的新判定；
  历史决策永久保留其原始版本号与哈希，结论不变。

## 告警语义

- 告警唯一键为 `(event_id, rule_id)`（稳定哈希 ID）：同一事件重复到达或
  同规则多次命中，全局只产生一条 `OPEN` 告警。
- 风险等级达到 `MEDIUM`（含）的命中才创建告警（阈值可配置）。
- 状态机：
  `OPEN --acknowledge--> ACKNOWLEDGED --resolve--> RESOLVED`
  ；`OPEN/ACKNOWLEDGED --ignore--> IGNORED`；`RESOLVED/IGNORED` 为终态。
- 处置请求必须携带 `idempotency_key`：
  - 相同幂等键重放 → `DUPLICATE`（返回首次结果，状态不变）；
  - 新请求重复已完成的同方向动作（如已 ACK 再 ACK）→ `DUPLICATE`；
  - 当前状态不允许的动作（如对 RESOLVED 再处置）→ `REJECTED`（HTTP 409）；
  - 并发处置同一告警时互斥执行，恰好一个请求 `APPLIED`，其余可区分
    `DUPLICATE`/`REJECTED`。
- 每次尝试（含重复与拒绝）都写审计流水，记录动作人、原因、前后状态、
  幂等键与结果。

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/v1/events` | 接入交易事件，返回 `ACCEPTED/DUPLICATE/REJECTED` |
| GET | `/v1/decisions` | 历史决策列表 |
| GET | `/v1/rejections` | 畸形事件拒绝记录 |
| POST | `/v1/rulesets` | 发布新版本规则集（重复版本 409） |
| GET | `/v1/rulesets` | 版本列表与当前版本/哈希 |
| POST | `/v1/rulesets/rollback` | 回滚到指定历史版本 |
| POST | `/v1/replay` | 按版本重放（`events` 或 `use_history:true`） |
| GET | `/v1/alerts?event_id=` | 告警列表/按事件过滤 |
| POST | `/v1/alerts/dispose` | 幂等处置（`acknowledge/resolve/ignore`） |
| GET | `/v1/alerts/{id}/audit` | 告警审计流水 |
| GET | `/healthz` | 健康检查 |

示例：

```bash
curl -X POST localhost:8080/v1/events -d '{
  "event_id":"e1","account_id":"ACCT-FRAUD-001","counterparty":"CP-1",
  "amount":100,"currency":"CNY","occurred_at":"2026-10-06T10:00:00Z"}'
```

## 版本兼容范围

- 规则集 `schema_version=1` 为当前唯一支持格式；其余版本发布即被拒绝。
- 决策/告警 JSON 字段名保持小写下划线兼容；Go 1.25+。
- 存储为进程内存态：重启后回到内置 `v1` 演示数据（设计上不依赖任何
  外部数据库或消息队列）。

## 代码结构

```
internal/model    领域模型（事件/决策/告警/审计/拒绝原因码）
internal/rules    不可变规则集、原子版本仓库、求值器（金额/频次/名单）
internal/engine   并发接入、去重、校验、计分顺序、只读历史重放
internal/alert    告警状态机、幂等处置、并发互斥、审计流水
internal/server   HTTP 接口
internal/testkit  测试构造工具（固定时钟、演示规则集、业务日志）
test/             端到端 HTTP 集成测试
cmd/server        服务入口
```

## 测试覆盖

`go test -v` 日志按业务域（规则判定 / 并发接入 / 乱序事件 / 畸形事件 /
规则变更与回放 / 告警生命周期 / 告警并发处置 / 端到端 HTTP）逐条打印
`【业务域】用例: ...` 与 PASS/FAIL 结果，可直接核对覆盖情况。
