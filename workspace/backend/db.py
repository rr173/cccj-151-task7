"""SQLite 持久化层。

进程重启后，已发布命令、出发记录、资源状态与剩余容量全部从此文件恢复。
所有写操作在 server 层的全局锁内串行执行（配合修订号实现乐观并发控制）。
"""
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- 受威胁网格（也作为路网节点）
CREATE TABLE IF NOT EXISTS grids(
  code       TEXT PRIMARY KEY,   -- 网格编号，导入幂等键
  name       TEXT NOT NULL,
  x          REAL NOT NULL,
  y          REAL NOT NULL,
  threatened INTEGER NOT NULL DEFAULT 1  -- 是否处于当前火线范围
);

-- 避难点
CREATE TABLE IF NOT EXISTS shelters(
  code         TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  x            REAL NOT NULL,
  y            REAL NOT NULL,
  beds         INTEGER NOT NULL,          -- 总床位
  accessible   INTEGER NOT NULL DEFAULT 0,-- 无障碍设施
  pets_allowed INTEGER NOT NULL DEFAULT 1,-- 接收宠物
  status       TEXT NOT NULL DEFAULT 'active' -- active | suspended
);

-- 道路（无向边）
CREATE TABLE IF NOT EXISTS roads(
  code     TEXT PRIMARY KEY,
  a        TEXT NOT NULL,
  b        TEXT NOT NULL,
  length   REAL NOT NULL DEFAULT 1,
  capacity INTEGER NOT NULL DEFAULT 1,    -- 单批次（波次）允许同时通过的车辆数
  status   TEXT NOT NULL DEFAULT 'open'   -- open | closed
);

-- 车辆
CREATE TABLE IF NOT EXISTS vehicles(
  code       TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  seats      INTEGER NOT NULL,
  accessible INTEGER NOT NULL DEFAULT 0,  -- 无障碍车辆
  status     TEXT NOT NULL DEFAULT 'available' -- available | down | departed
);

-- 家庭（不可拆分单元）。ref 为外部户号，重复导入按 ref 去重
CREATE TABLE IF NOT EXISTS households(
  ref      TEXT PRIMARY KEY,
  name     TEXT NOT NULL DEFAULT '',
  grid     TEXT NOT NULL,
  members  INTEGER NOT NULL,
  mobility INTEGER NOT NULL DEFAULT 0,    -- 行动辅助需求（需轮椅通道）
  pets     INTEGER NOT NULL DEFAULT 0,    -- 宠物数量
  contact  TEXT NOT NULL DEFAULT ''
);

-- 候选方案 / 已发布方案
CREATE TABLE IF NOT EXISTS plans(
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  commander     TEXT NOT NULL DEFAULT '',
  base_revision INTEGER NOT NULL,         -- 制定时的数据修订号
  status        TEXT NOT NULL DEFAULT 'candidate', -- candidate | published | superseded
  payload       TEXT NOT NULL,            -- JSON：批次、安置、不可行诊断
  created_at    REAL NOT NULL
);

-- 撤离令
CREATE TABLE IF NOT EXISTS orders(
  id          TEXT PRIMARY KEY,
  plan_id     TEXT NOT NULL,
  commander   TEXT NOT NULL DEFAULT '',
  revision    INTEGER NOT NULL,
  created_at  REAL NOT NULL
);

-- 撤离批次
CREATE TABLE IF NOT EXISTS batches(
  id           TEXT PRIMARY KEY,
  order_id     TEXT NOT NULL,
  seq          INTEGER NOT NULL,
  wave         INTEGER NOT NULL,          -- 出发波次
  vehicle_code TEXT NOT NULL,
  grid         TEXT NOT NULL,            -- 出发点（家庭所在网格）
  shelter_code TEXT NOT NULL,
  route        TEXT NOT NULL,            -- JSON 边编号数组
  status       TEXT NOT NULL DEFAULT 'scheduled', -- scheduled | departed | cancelled
  departed_at  REAL
);

-- 家庭→批次 安置记录
CREATE TABLE IF NOT EXISTS assignments(
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  batch_id    TEXT NOT NULL,
  household_ref TEXT NOT NULL,
  UNIQUE(household_ref, batch_id)
);

-- 事件审计日志（火线扩大、封路、车辆故障、避难点暂停等）
CREATE TABLE IF NOT EXISTS event_log(
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      REAL NOT NULL,
  kind    TEXT NOT NULL,
  detail  TEXT NOT NULL,
  revision INTEGER NOT NULL
);

-- ===================== 推演分支（隔离沙盒） =====================
-- 分支元数据保存在实战库；分支的业务数据在独立 SQLite 文件中（物理隔离）。
CREATE TABLE IF NOT EXISTS branches(
  id                 TEXT PRIMARY KEY,
  name               TEXT NOT NULL,
  status             TEXT NOT NULL DEFAULT 'active', -- active | discarded
  base_live_revision INTEGER NOT NULL,   -- 创建时实战修订号（创建基线）
  base_fingerprint   TEXT NOT NULL,      -- 创建基线资源指纹（永不改写，审计用）
  baseline_fingerprint TEXT NOT NULL,    -- 三方合并所用 merge-base（提升成功后刷新）
  baseline_revision  INTEGER NOT NULL,   -- merge-base 对应的实战修订号
  db_file            TEXT NOT NULL,      -- 分支独立数据库文件（相对/绝对路径）
  idem_key           TEXT UNIQUE,        -- 创建幂等键
  created_at         REAL NOT NULL,
  discarded_at       REAL
);

-- 分支生命周期审计（创建/废弃/提升的尝试与结果，重启后仍可查）
CREATE TABLE IF NOT EXISTS branch_audit(
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          REAL NOT NULL,
  branch_id   TEXT NOT NULL,
  action      TEXT NOT NULL,             -- create | simulate | promote_ok | promote_rejected | discard
  detail      TEXT NOT NULL,
  op_id       TEXT
);

-- 幂等操作记录：模拟写操作（op_id）与提升（promote_id）的请求/响应
CREATE TABLE IF NOT EXISTS sim_ops(
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  scope      TEXT NOT NULL,              -- 分支 id（或 'live'）
  op_id      TEXT NOT NULL,
  response   TEXT NOT NULL,
  ts         REAL NOT NULL,
  UNIQUE(scope, op_id)
);

-- ===================== 离线车队回执中继对接 =====================
-- 中继回调的幂等台账：同一 idempotency_key 永远返回首次响应（中继安全重试/恰好一次）
CREATE TABLE IF NOT EXISTS relay_callbacks(
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  idempotency_key TEXT NOT NULL UNIQUE,
  batch_id       TEXT NOT NULL DEFAULT '',
  seq            INTEGER,
  receipt_no     TEXT NOT NULL DEFAULT '',
  type           TEXT NOT NULL DEFAULT '',
  response_json  TEXT NOT NULL,          -- 首次响应留痕（重放原样返回）
  ts             REAL NOT NULL
);

-- 出站执行包导出快照（首次导出即不可变；回调据此识别车辆/目的地变化）
CREATE TABLE IF NOT EXISTS execution_exports(
  batch_id      TEXT PRIMARY KEY,
  vehicle_code  TEXT NOT NULL,
  shelter_code  TEXT NOT NULL,
  vehicle_status TEXT NOT NULL DEFAULT '',
  shelter_status TEXT NOT NULL DEFAULT '',
  package_hash  TEXT NOT NULL DEFAULT '',
  exported_at   REAL NOT NULL
);

-- ===================== 运营审计：审批追踪工作台 =====================
-- 审批决策只追加台账（append-only；任何 UPDATE/DELETE 都被视为破坏审计完整性）。
-- 一条申请从 submitted -> approved/rejected/expired/exec_failed 用相同 request_id
-- 串成可检索时间线；seq 为单调游标，报表截面就是某个 seq 水位。
CREATE TABLE IF NOT EXISTS approval_decisions(
  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id  TEXT NOT NULL,             -- 同一申请的多条决策共享（如方案 id / 批次 id）
  ts          REAL NOT NULL,             -- 事件时刻（unix 秒）
  actor       TEXT NOT NULL DEFAULT '',  -- 操作者（发起/执行动作的人或系统）
  reviewer    TEXT NOT NULL DEFAULT '',  -- 复核者（批准/拒绝动作的责任人）
  action_kind TEXT NOT NULL,             -- 动作种类，见 approval.ALLOWED_ACTIONS
  result      TEXT NOT NULL,             -- submitted | approved | rejected | expired | exec_failed
  target_type TEXT NOT NULL DEFAULT '',  -- 对象类型：plan | batch | vehicle | shelter | road
  target_ref  TEXT NOT NULL DEFAULT '',  -- 对象编号
  detail      TEXT NOT NULL DEFAULT '{}', -- JSON 明细（决定/失败原因等，紧凑序列化）
  dedup_key   TEXT UNIQUE                -- 防重键：同键决策只入账一次（演示重灌/重试用）
);
CREATE INDEX IF NOT EXISTS idx_approval_ts ON approval_decisions(ts);
CREATE INDEX IF NOT EXISTS idx_approval_request ON approval_decisions(request_id);
CREATE INDEX IF NOT EXISTS idx_approval_filter ON approval_decisions(action_kind, result, actor, reviewer);

-- 审计身份与观察权限（演示用轻量模型；以 X-Audit-User 头标识主体）。
CREATE TABLE IF NOT EXISTS audit_principals(
  login       TEXT PRIMARY KEY,
  name        TEXT NOT NULL DEFAULT '',
  role        TEXT NOT NULL,             -- auditor | reviewer | planner | ops
  can_observe INTEGER NOT NULL DEFAULT 0,-- 是否拥有审批观察权限
  token       TEXT NOT NULL DEFAULT '',  -- 下载访问令牌（?token=，便于浏览器直接下载）
  created_at  REAL NOT NULL
);

-- 查询游标：持久化（重启仍可校验），带过滤器签名与过期时刻。
CREATE TABLE IF NOT EXISTS audit_cursors(
  token       TEXT PRIMARY KEY,          -- 不透明游标令牌
  filter_hash TEXT NOT NULL,             -- 创建时过滤条件规范化哈希（换条件必须重新开查）
  after_seq   INTEGER NOT NULL,          -- 已读到的最后一个 seq
  page_limit  INTEGER NOT NULL,
  expires_at  REAL NOT NULL,
  created_at  REAL NOT NULL
);

-- 报表截面：创建时锁定 snapshot_seq；行内容在创建时物化冻结，
-- 之后新增决策绝不改写先前截面。JSON/CSV 仅对同一冻结行集做不同渲染。
CREATE TABLE IF NOT EXISTS audit_reports(
  id          TEXT PRIMARY KEY,
  filter_hash TEXT NOT NULL,             -- 锁定时的过滤条件规范化哈希
  filter_json TEXT NOT NULL,             -- 过滤条件原文（回显用）
  snapshot_seq INTEGER NOT NULL,         -- 截面水位：只含 seq <= 该值的决策
  snapshot_ts REAL NOT NULL,             -- 锁定时刻
  created_by  TEXT NOT NULL DEFAULT '',
  idem_key    TEXT UNIQUE,               -- 重复点击下载的幂等键
  row_count   INTEGER NOT NULL,
  rows_json   TEXT NOT NULL,             -- 冻结行（固定字段/顺序），两格式共用
  sha256      TEXT NOT NULL,             -- rows_json 规范序列化的 SHA256（完整性校验）
  created_at  REAL NOT NULL
);
"""


class DB:
    def __init__(self, path):
        self.path = path
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()
        if self.get_meta("revision") is None:
            self.set_meta("revision", "0")

    def _migrate(self):
        """对老库幂等补列/补索引（CREATE TABLE IF NOT EXISTS 不会改变已存在的表）。"""
        cols = {r["name"] for r in self.conn.execute(
            "PRAGMA table_info(approval_decisions)")}
        if cols and "dedup_key" not in cols:
            self.conn.execute(
                "ALTER TABLE approval_decisions ADD COLUMN dedup_key TEXT")
        # 新库（列随建表存在）与老库（刚补列）统一在这里建唯一索引
        self.conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_dedup"
            " ON approval_decisions(dedup_key)")

    # ---- meta / revision ----
    def get_meta(self, key):
        r = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return r["value"] if r else None

    def set_meta(self, key, value):
        self.conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        self.conn.commit()

    def revision(self):
        return int(self.get_meta("revision"))

    def bump_revision(self):
        v = self.revision() + 1
        self.set_meta("revision", v)
        return v

    def log_event(self, kind, detail):
        self.conn.execute(
            "INSERT INTO event_log(ts,kind,detail,revision) VALUES(?,?,?,?)",
            (time.time(), kind, detail, self.revision()),
        )

    def commit(self):
        self.conn.commit()
