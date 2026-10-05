# API 说明

所有接口均在全局事务锁内串行执行；写接口成功后数据修订号 `revision` 单调递增。
请求/响应均为 `application/json; charset=utf-8`。

## 资源模型

| 对象 | 关键字段 | 说明 |
|---|---|---|
| 网格 `grids` | `code,name,x,y,threatened` | 受威胁网格是路网节点与家庭位置 |
| 道路 `roads` | `code,a,b,length,capacity,status` | 无向边；`capacity`=单波次可并发通过的车辆数；`status=open/closed` |
| 避难点 `shelters` | `code,name,x,y,beds,accessible,pets_allowed,status` | `status=active/suspended` |
| 车辆 `vehicles` | `code,name,seats,accessible,status` | `status=available/down/departed` |
| 家庭 `households` | `ref,name,grid,members,mobility,pets,contact` | `ref` 为外部户号，**家庭不可拆分**，重复 `ref` 不重复登记 |

容量口径：床位按**人数**计；车辆座位按 `members + pets`（宠物占座）；
道路容量按**车辆批次**计；已出发（`departed`）占用永久锁定。

## 接口

### 状态
- `GET /api/state` — 全量态势：网格/道路/避难点/车辆/家庭、批次与安置、
  每户状态、各避难点 `committed/reserved/remaining` 床位、修订号、最近事件。
- `GET /api/events` — 审计事件流。

### 导入与登记（幂等）
- `POST /api/import/grids` `/roads` `/shelters` `/vehicles`
  - 体：对象数组（或 `{"items":[...]}`）。按 `code` upsert，重复导入覆盖更新、不产生重复行。
- `POST /api/households`
  - 单个对象或数组；同 `ref` 已存在则跳过（`skipped_duplicates` 计数，且不覆盖原登记）。

### 规划与发布
- `POST /api/plan` `{"name","commander"}`
  - 仅对**受威胁网格中尚未出发**的家庭求解；返回
    `feasible,max_wave,batches[],unassigned[],capacity,totals` 及方案 `id`。
  - 不改变任何已发布命令，可反复调用以比较候选方案。
- `GET /api/plans` / `GET /api/plans/{id}` — 候选与历史方案列表/详情。
- `POST /api/plans/{id}/publish` `{"commander"}`
  - 发布分区撤离令。乐观并发：方案 `base_revision` 必须等于当前 `revision`，
    否则返回 **409**（已有他人发布，或路况/资源已变化），需重新规划。
  - 不可行方案、空方案、违反硬约束的方案一律 409 拒绝。
  - 发布即替换全部**未出发**计划批次；已出发批次与其床位占用原样保留。

### 执行（承诺）
- `POST /api/batches/{id}/depart`
  - 车辆离场：批次置 `departed`、车辆置 `departed`、目的地床位计入 `committed`。
    同一辆车后续未出发批次自动撤回（`cancelled`）等待重新编排。
  - **承诺不可逆**：之后任何事件与重新规划都不会改派该户或释放其床位。

### 态势事件（只影响未出发批次）
`POST /api/events`，按 `type`：
- `road_close {"code"}` — 封闭道路；路径经过该道路的未出发批次撤回。
- `road_open {"code"}` — 恢复道路，之后可继续编排。
- `vehicle_down / vehicle_recovered {"code"}`
- `shelter_suspend / shelter_resume {"code"}`
- `fire_expand {"code","close_roads":[...]}` — 火线扩大，可同时封路。
- `fire_clear {"code"}` — 网格解除威胁。

返回均含 `revision` 与 `released_for_replan`（被撤回待重排的户号）。

### 运维
- `POST /api/reset` — 清空并恢复演示数据（同时清空推演分支元数据与分支库文件）。

## 推演分支（隔离沙盒）

分支是**独立 SQLite 文件**（创建时对实战库做完整物理备份）。分支下的所有写操作
只落在分支库，实战库不受任何影响；提升(promote)是唯一把推演资源改动合并回实战的通道。
分支地址统一为 `/api/branches/{id}/...`；分支内写接口体可带 `op_id`（客户端生成的
幂等键），相同 `op_id` 的重试返回首次结果，不重复执行。

### 分支管理
- `POST /api/branches` `{"name","idem_key?"}`
  - 从**当前实战态势**复制出隔离分支；返回 `id`、`base_live_revision`（创建基线修订号）。
  - `idem_key` 相同的重复创建返回同一分支（`idempotent_replay:true`）。
- `GET /api/branches` — 分支列表（id/name/status/创建基线/上次提升修订号/时间）。
- `POST /api/branches/{id}/discard` — 废弃分支（幂等）。废弃后禁止再写；
  分支文件与审计保留，差异仍可只读查看。
- `GET /api/branches/{id}/audit` — 分支生命周期审计
 （create / simulate / promote_ok / promote_rejected / discard，含操作细节与 op_id）。

### 分支内连续模拟（全部隔离、幂等、可重启恢复）
分支支持的写接口与实战同构（路径前加 `/api/branches/{id}`）：
- `POST /api/branches/{id}/events`（态势事件，体可含 `op_id`）
- `POST /api/branches/{id}/plan`
- `POST /api/branches/{id}/plans/{pid}/publish`
- `POST /api/branches/{id}/batches/{bid}/depart`

只读：`GET .../state`、`GET .../plans`、`GET .../plans/{pid}`、`GET .../events`。
返回体带 `context:{kind:"branch",id,name,...}` 以明确上下文。

### 并排差异
- `GET /api/branches/{id}/diff`
  - `people[]`：每户在实战/推演的去向（status/shelter/wave，`differs` 标记）；
  - `shelters[]`：两侧床位 `beds/committed/reserved/remaining/status`；
  - `blockers[]`：两侧最新方案的受阻原因（按户）；
  - `resource_fields[]`：三方（base/live/branch）逐字段判定
    （`branch_only` 可提升 / `live_only` / `same_change` / `commitment` / `conflict`）；
  - 附双方修订号、命令数、已离场/待安排户数汇总。

### 提升（三方冲突检查）
- `POST /api/branches/{id}/promote`
  `{"expected_live_revision":<打开差异时看到的实战修订号>, "promote_id":"<幂等键>"}`
  - **按创建基线**对每个被跟踪字段（道路 status/capacity、避难点 status/beds、
    车辆 status、网格 threatened）做 base/实战/推演三方比较：
    - 仅推演改过（实战相对基线未动）→ 干净改动，应用；
    - 两边改成相同值 → 无冲突、无需应用；
    - 两边都改且值不同 → 冲突；
  - `expected_live_revision` 与当前实战修订号不一致 → **过期基线，409 stale_baseline**；
  - 存在任一冲突 → **整体拒绝（409 conflict）**，不写任何实战数据；
    返回 `conflict_objects`（`表:编号`）与 `conflicts[]`（对象、字段、base/live/branch 三值），
    以及 `pending_clean_changes`；
  - 成功时返回 `applied_fields`、新 `revision`、因状态变化而撤回待重排的户、
    `skipped_commitments`；
  - **只迁移资源字段**：推演产生的命令、批次、离场记录、已承诺床位/车辆占用永不带入实战
    （分支内车辆 `departed` 标记为 `commitment` 自动忽略）；
  - 相同 `promote_id` 重放返回首次结果（成功或被拒），凭证持久化、重启后仍有效。

## 硬约束（规划器与发布前校验器双重保证）

1. 床位：`已承诺 + 本方案安置人数 ≤ 总床位`；
2. 座位：`成员 + 宠物数 ≤ 车辆座位`；
3. 行动辅助户只能乘无障碍车辆、进入无障碍避难点；
4. 携带宠物户只能进入 `pets_allowed` 避难点；
5. 路径必须全部由 `open` 道路连续构成（系统不安排家庭自行经过关闭路段）；
6. 同一波次同一条道路上的批次数 ≤ 道路容量；同一车辆同一波次最多一批；
7. 暂停接收的避难点、故障/已离场车辆不得使用；
8. 每个待撤离家庭恰好安置一次；已出发家庭不得被重新分配。

无可行解时，`unassigned[]` 按户给出具体阻断原因（封路、无障碍车不足、
座位不足、某避难点剩余床位、户间竞争耗尽床位、道路时序瓶颈等）。

## 离线车队回执中继对接面

独立模块（[relay/](relay/)，端口 8090）经下列接口与本系统连接：

- `GET /api/execution-packages?status=scheduled` — 可导出批次列表。
- `GET /api/execution-package/v1/{batch_id}` — 不可变执行包
  （`batch_ref`=批次 id，含摘要、车辆、目的地、路径、搭载家庭；
  首次导出在 `execution_exports` 留车辆/目的地快照）。
- `POST /api/relay-callback` — 中继按序转发的回执：
  - 按 `idempotency_key` 幂等，重复调用返回首次响应（台账 `relay_callbacks`）；
  - 批次不存在/已撤回 → `{"result":"rejected","reason":"batch_withdrawn"}`；
  - 车辆相对导出快照被改派或已故障下线 → `vehicle_changed`；
  - 目的地被改派或避难点已暂停 → `destination_changed`；
  - 合法回执返回 `{"result":"ack"}`；`departed` 类联动既有离场承诺语义。

中继自身 API（执行包导入、终端下载、批量回执、重试、审计）见 [relay/API.md](relay/API.md)。

## 运营审计：审批追踪工作台

独立的审计视图（[backend/approval.py](backend/approval.py)），与编排业务共享数据库但**只追加**：
每条撤离令/批次的申请、批准、拒绝、失效、执行失败都以 `request_id` 串成时间线
（`approval_decisions`，`seq` 单调递增，永不变更/删除）。业务动作（方案提交、发布批准/
拒绝、乐观并发过期、撤回失效、离场执行、中继回执）自动落账，也可人工录入备注。

### 身份与观察权限（演示轻量模型）

- 所有 `/api/audit/*` 请求需头 `X-Audit-User: <login>`；浏览器直连下载可用 `?token=<下载令牌>`。
- 预置身份：`auditor.lin`（审计，可观察）、`reviewer.wen`（复核，可观察）、
  `planner.tu`（调度，无观察权）、`ops.wu`（车班，无观察权）。
- 错误：缺身份 **401 unauthenticated**；未知身份/坏令牌 **403 unknown_principal / bad_download_token**；
  无观察权限 **403 observe_forbidden**。
- `GET /api/audit/principals`（公开，不含令牌）、`GET /api/audit/whoami`。

### 时间线查询：组合过滤 + 游标分段

`GET /api/audit/decisions`，查询参数（可任意组合，重复/逗号分隔支持多值）：

| 参数 | 含义 | 校验 |
|---|---|---|
| `request_id` | 申请编号（单值），拉出一条申请的完整生命周期链 | 长度 ≤80 |
| `actor` | 操作者（单值） | 长度 ≤64 |
| `reviewer` | 复核者（单值） | 长度 ≤64 |
| `action` | 动作种类，多值 | `order_submit/order_approve/order_reject/batch_depart/batch_expire/relay_receipt/manual_note` |
| `result` | 结果状态，多值 | `submitted/approved/rejected/expired/exec_failed` |
| `time_from` / `time_to` | 起止时刻（epoch 秒或 ISO 8601，含端点） | 起始不得晚于截止 |
| `limit` | 每段条数 | 1..200，默认 50 |
| `cursor` | 上一段响应里的 `next_cursor`（不透明） | 见下 |

- 未知参数名、非法枚举/时间/limit 一律 **400 invalid_filter**（中文消息明确指出出错字段）。
- 响应按 `seq` 倒序：`{filters,total_matching,page_size,next_cursor,cursor_expires_in,fields,decisions[]}`。
- 游标**与创建时过滤条件签名绑定**：分页中改动任何过滤值 → **400 cursor_filter_mismatch**；
  游标不存在/被伪造 → **410 cursor_expired**；超过 TTL（默认 1800s，`EVAC_CURSOR_TTL` 可调）
  → **410 cursor_expired**。游标持久化在 `audit_cursors`，**进程重启后仍可续读**。

### 截面锁定报表（JSON / CSV 同一份内容）

- `POST /api/audit/reports`，体为过滤条件（同查询参数名）+ 可选 `idem_key`。
  - 创建瞬间锁定水位 `snapshot_seq = 当前最大 seq`，并把命中行**物化冻结**到 `audit_reports`；
  - 相同 `idem_key` 重试返回同一报表（`idempotent_replay:true`）；前端按过滤条件哈希生成稳定键，
    重复点击下载只能拿到同一份文件。
- `GET /api/audit/reports` — 报表列表；`GET /api/audit/reports/{id}` — 元数据。
- `GET /api/audit/reports/{id}/content?format=json|csv`（需观察权限或 `?token=`）。
  - 两格式**字段、顺序、明细逐格相同**，字段固定为：
    `seq, ts(UTC ISO), request_id, actor, reviewer, action_kind, result, target_type, target_ref, detail`
    （`detail` 在 JSON 与 CSV 中都是同一段紧凑 JSON 文本）；
  - 输出确定（固定键序/换行），任意时刻重复下载**字节级一致**；带 `ETag`（冻结内容 SHA256）；
  - 读取时复核 SHA256，冻结内容被篡改/损坏 → **500 snapshot_tampered**；
  - **进程重启后旧报表仍可校验、读取**；截面之后新增的决策绝不进入先前报表
    （新报表才会看到更高水位）。非法格式 **400 bad_format**，未知报表 **404 not_found**。
- `POST /api/audit/decisions`（任意已登记身份）人工录入一条决策；
  `POST /api/audit/reset-demo`（需观察权限）恢复演示时间线。

