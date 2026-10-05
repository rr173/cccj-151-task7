"""运营审计 —— 审批追踪工作台核心。

数据模型（表结构见 db.py）
  * approval_decisions：只追加决策台账。seq 单调递增，是天然的时间线游标；
    一条申请（request_id）的 submitted/approved/rejected/expired/exec_failed
    多决策串成完整生命周期。
  * audit_cursors：分页游标持久化，绑定创建时的过滤条件签名与过期时刻；
    进程重启后仍可校验，过期/被清理即明确失效。
  * audit_reports：报表在创建瞬间锁定 snapshot_seq 截面并**物化冻结行集**，
    JSON 与 CSV 只是同一冻结行的两种渲染；之后新决策绝不改写先前截面，
    重复点击下载拿到字节级同一份文件。

权限（演示用轻量模型）
  * 请求头 X-Audit-User 标识主体；无该头 401 unauthenticated，未知主体 403 unknown_principal；
  * 查询时间线/生成/读取报表需要 can_observe，否则 403 observe_forbidden；
  * 浏览器直连下载可改用 ?token=<主体访问令牌>。

错误（机器可读 code，便于前端区分提示）
  401 unauthenticated / 403 unknown_principal / observe_forbidden / bad_download_token
  400 invalid_filter / cursor_filter_mismatch / bad_request
  410 cursor_expired / 404 not_found / 409 idempotency_conflict / 500 snapshot_tampered
"""
import csv
import hashlib
import io
import json
import secrets
import time
from datetime import datetime, timezone

SCHEMA_NAME = "evac.audit-report/v1"

# 动作种类（封闭集合；过滤/录入值不合法即 400）
ALLOWED_ACTIONS = (
    "order_submit",     # 撤离令申请
    "order_approve",    # 批准
    "order_reject",     # 拒绝
    "batch_depart",     # 批次离场执行
    "batch_expire",     # 批次失效（撤回）
    "relay_receipt",    # 中继回执
    "manual_note",      # 人工备注
)

# 结果状态（封闭集合）：申请 / 批准 / 拒绝 / 失效 / 执行失败
ALLOWED_RESULTS = ("submitted", "approved", "rejected", "expired", "exec_failed")

# 报表与时间线统一字段（JSON / CSV 字段、顺序、明细完全一致）
FIELDS = ["seq", "ts", "request_id", "actor", "reviewer", "action_kind",
          "result", "target_type", "target_ref", "detail"]

ALLOWED_TARGET_TYPES = ("", "plan", "batch", "vehicle", "shelter", "road", "household", "other")

# 允许识别的过滤参数名（出现未知参数即 400，避免调用方误以为过滤生效）
FILTER_PARAMS = {"actor", "reviewer", "action", "result", "time_from", "time_to",
                 "request_id"}

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
CURSOR_TTL_SECONDS = float(__import__("os").environ.get("EVAC_CURSOR_TTL", "1800"))


class AuditError(Exception):
    def __init__(self, status, code, message, extra=None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.extra = extra or {}


# ---------------------------------------------------------------- 身份与权限

DEMO_PRINCIPALS = [
    # login, 姓名, 角色, 观察权限, 下载令牌
    ("auditor.lin", "林审计", "auditor", 1, "tok-auditor-lin"),
    ("reviewer.wen", "闻复核", "reviewer", 1, "tok-reviewer-wen"),
    ("planner.tu", "图调度", "planner", 0, "tok-planner-tu"),
    ("ops.wu", "车班老吴", "ops", 0, "tok-ops-wu"),
]


def ensure_principals(d):
    """幂等播种审计身份（重复执行不覆盖、不重复）。"""
    for login, name, role, can, token in DEMO_PRINCIPALS:
        d.conn.execute(
            "INSERT OR IGNORE INTO audit_principals(login,name,role,can_observe,token,created_at)"
            " VALUES(?,?,?,?,?,?)",
            (login, name, role, can, token, time.time()))
    d.commit()


def list_principals(d):
    return [dict(r) for r in d.conn.execute(
        "SELECT login,name,role,can_observe FROM audit_principals ORDER BY login")]


def authenticate(d, login_header=None, token=None):
    """解析主体。header 优先；否则按下载令牌识别。返回 principal dict。"""
    if login_header:
        login = login_header.strip()
        if not login:
            raise AuditError(401, "unauthenticated",
                             "缺少身份标识：请在审计工作台选择审计身份（X-Audit-User）")
        r = d.conn.execute("SELECT * FROM audit_principals WHERE login=?", (login,)).fetchone()
        if not r:
            raise AuditError(403, "unknown_principal",
                             f"未知审计身份 {login}，请选择已登记的审计/复核账号")
        return dict(r)
    if token:
        r = d.conn.execute("SELECT * FROM audit_principals WHERE token=?", (token,)).fetchone()
        if not r:
            raise AuditError(403, "bad_download_token", "下载令牌无效或已吊销")
        return dict(r)
    raise AuditError(401, "unauthenticated",
                     "缺少身份标识：请在审计工作台选择审计身份（X-Audit-User）")


def require_observer(d, login_header=None, token=None):
    p = authenticate(d, login_header, token)
    if not p["can_observe"]:
        raise AuditError(403, "observe_forbidden",
                         f"身份 {p['name']}（{p['role']}）没有审批观察权限，"
                         "审批追踪仅对审计/复核角色开放")
    return p


# ---------------------------------------------------------------- 过滤条件

def _parse_ts(value, field):
    """时间参数：epoch 秒（数字）或 ISO 8601 字符串。"""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    s = str(value).strip()
    if not s:
        raise AuditError(400, "invalid_filter", f"{field} 不能为空")
    try:
        return float(s)
    except ValueError:
        pass
    try:
        iso = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        raise AuditError(400, "invalid_filter",
                         f"{field} 时间格式不合法：{s!r}（应为 epoch 秒或 ISO 8601）")


def _parse_multi(raw):
    """逗号分隔/重复参数都支持；去空白、去重、去空项，保持传入顺序。"""
    out = []
    for chunk in raw:
        for v in str(chunk).split(","):
            v = v.strip()
            if v and v not in out:
                out.append(v)
    return out


def normalize_filters(getter, known_only=True):
    """把查询参数/请求体规范化为 (where_sql, params, normalized, filter_hash)。

    getter(name) -> list[str]（查询串）或标量（请求体）。
    未知参数、非法枚举/时间一律 400 invalid_filter。
    """
    extra_allowed = {"limit", "cursor", "format", "token", "idem_key",
                     "client_token"}
    if callable(getter) and not isinstance(getter, dict):
        def values(name):
            v = getter(name)
            if v is None:
                return []
            return v if isinstance(v, list) else [v]
        param_names = getattr(getter, "param_names", None)
    else:
        src = getter or {}

        def values(name):
            if name not in src or src[name] in (None, ""):
                return []
            v = src[name]
            return v if isinstance(v, list) else [v]
        param_names = set(src.keys()) if known_only else None

    if known_only and param_names:
        extra = set(param_names) - FILTER_PARAMS - extra_allowed
        if extra:
            raise AuditError(
                400, "invalid_filter",
                f"存在不支持的过滤参数 {sorted(extra)}；支持：{sorted(FILTER_PARAMS)}")

    clauses, params = ["1=1"], []
    norm = {}

    actions = _parse_multi(values("action"))
    for a in actions:
        if a not in ALLOWED_ACTIONS:
            raise AuditError(400, "invalid_filter",
                             f"动作种类不合法：{a!r}；可选 {list(ALLOWED_ACTIONS)}")
    if actions:
        clauses.append("action_kind IN (%s)" % ",".join("?" * len(actions)))
        params.extend(actions)
        norm["action"] = actions

    results = _parse_multi(values("result"))
    for r in results:
        if r not in ALLOWED_RESULTS:
            raise AuditError(400, "invalid_filter",
                             f"结果状态不合法：{r!r}；可选 {list(ALLOWED_RESULTS)}")
    if results:
        clauses.append("result IN (%s)" % ",".join("?" * len(results)))
        params.extend(results)
        norm["result"] = results

    for name, col in (("actor", "actor"), ("reviewer", "reviewer")):
        vals = [str(v).strip() for v in values(name) if str(v).strip()]
        if len(vals) > 1:
            raise AuditError(400, "invalid_filter", f"{name} 只接受一个值")
        if vals:
            if len(vals[0]) > 64:
                raise AuditError(400, "invalid_filter", f"{name} 长度不能超过 64")
            clauses.append(f"{col}=?")
            params.append(vals[0])
            norm[name] = vals[0]

    rid_vals = [str(v).strip() for v in values("request_id") if str(v).strip()]
    if len(rid_vals) > 1:
        raise AuditError(400, "invalid_filter", "request_id 只接受一个值")
    if rid_vals:
        if len(rid_vals[0]) > 80:
            raise AuditError(400, "invalid_filter", "request_id 长度不能超过 80")
        clauses.append("request_id=?")
        params.append(rid_vals[0])
        norm["request_id"] = rid_vals[0]

    t_from = values("time_from")
    t_to = values("time_to")
    tf = _parse_ts(t_from[0], "time_from") if t_from else None
    tt = _parse_ts(t_to[0], "time_to") if t_to else None
    if tf is not None:
        clauses.append("ts>=?")
        params.append(tf)
        norm["time_from"] = tf
    if tt is not None:
        clauses.append("ts<=?")
        params.append(tt)
        norm["time_to"] = tt
    if tf is not None and tt is not None and tf > tt:
        raise AuditError(400, "invalid_filter",
                         f"起始时刻 {tf} 晚于截止时刻 {tt}，时间区间不合法")

    where = " AND ".join(clauses)
    digest = hashlib.sha256(
        json.dumps(norm, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:32]
    return where, params, norm, digest


def filters_from_qs(qs):
    """从 parse_qs 的 dict 构造 getter（未知参数检查用）。"""
    def getter(name):
        return qs.get(name)
    getter.param_names = set(qs.keys())
    return getter


# ---------------------------------------------------------------- 行渲染

def iso_ts(ts):
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") \
        + ("%03d" % int(round((float(ts) % 1) * 1000))) + "Z"


def _clean_detail(raw):
    """明细统一为紧凑、键排序的 JSON 文本（两格式逐字相同）。"""
    if raw is None or raw == "":
        obj = {}
    elif isinstance(raw, str):
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            obj = {"text": raw}
    else:
        obj = raw
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def render_row(r):
    """DB 行 -> 报表/时间线统一 dict（字段顺序固定）。"""
    return {
        "seq": r["seq"],
        "ts": iso_ts(r["ts"]),
        "request_id": r["request_id"],
        "actor": r["actor"],
        "reviewer": r["reviewer"],
        "action_kind": r["action_kind"],
        "result": r["result"],
        "target_type": r["target_type"],
        "target_ref": r["target_ref"],
        "detail": _clean_detail(r["detail"]),
    }


# ---------------------------------------------------------------- 决策写入（内部钩子 + 人工录入）

def record_decision(d, action_kind, result, request_id, actor="", reviewer="",
                    target_type="", target_ref="", detail=None, ts=None,
                    dedup_key=None):
    """追加一条审批决策（只追加；不触碰业务修订号）。

    dedup_key 命中（演示重灌/重试）时不重复入账，直接返回已存在的 seq。
    """
    if action_kind not in ALLOWED_ACTIONS:
        raise AuditError(400, "bad_request", f"动作种类不合法：{action_kind}")
    if result not in ALLOWED_RESULTS:
        raise AuditError(400, "bad_request", f"结果状态不合法：{result}")
    if target_type not in ALLOWED_TARGET_TYPES:
        raise AuditError(400, "bad_request", f"对象类型不合法：{target_type}")
    ts = float(ts) if ts is not None else time.time()
    if dedup_key:
        old_row = d.conn.execute(
            "SELECT seq FROM approval_decisions WHERE dedup_key=?", (dedup_key,)).fetchone()
        if old_row:
            return old_row["seq"]
    cur = d.conn.execute(
        "INSERT INTO approval_decisions(request_id,ts,actor,reviewer,action_kind,result,"
        "target_type,target_ref,detail,dedup_key) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (str(request_id), ts, str(actor), str(reviewer), action_kind, result,
         target_type, str(target_ref), _clean_detail(detail), dedup_key))
    d.commit()
    return cur.lastrowid


def create_manual_decision(d, principal, body):
    """人工录入决策（任何已登记身份可用；操作者默认为录入人）。"""
    body = body or {}
    rid = str(body.get("request_id") or "").strip()
    if not rid:
        raise AuditError(400, "bad_request", "缺少 request_id（申请编号，用于串联时间线）")
    action = body.get("action_kind")
    result = body.get("result")
    if action not in ALLOWED_ACTIONS:
        raise AuditError(400, "bad_request",
                         f"动作种类不合法：{action!r}；可选 {list(ALLOWED_ACTIONS)}")
    if result not in ALLOWED_RESULTS:
        raise AuditError(400, "bad_request",
                         f"结果状态不合法：{result!r}；可选 {list(ALLOWED_RESULTS)}")
    ttype = body.get("target_type", "")
    if ttype not in ALLOWED_TARGET_TYPES:
        raise AuditError(400, "bad_request",
                         f"对象类型不合法：{ttype!r}；可选 {list(ALLOWED_TARGET_TYPES)}")
    detail = body.get("detail", {})
    if not isinstance(detail, (dict, list)):
        raise AuditError(400, "bad_request", "detail 必须是 JSON 对象或数组")
    ts = _parse_ts(body["ts"], "ts") if body.get("ts") else None
    seq = record_decision(
        d, action, result, rid,
        actor=str(body.get("actor") or principal["name"]),
        reviewer=str(body.get("reviewer") or ""),
        target_type=ttype, target_ref=str(body.get("target_ref", "")),
        detail=detail, ts=ts)
    r = d.conn.execute("SELECT * FROM approval_decisions WHERE seq=?", (seq,)).fetchone()
    return render_row(r)


# ---------------------------------------------------------------- 游标分页查询

def _query_rows(d, where, params, limit, after_seq=None):
    sql = f"SELECT * FROM approval_decisions WHERE {where}"
    p = list(params)
    if after_seq is not None:
        sql += " AND seq<?"
        p.append(after_seq)
    # 多取一条判断是否还有后续，避免给最后一页也颁发空游标
    sql += " ORDER BY seq DESC LIMIT ?"
    p.append(limit + 1)
    fetched = [render_row(r) for r in d.conn.execute(sql, p).fetchall()]
    has_more = len(fetched) > limit
    return fetched[:limit], has_more


def query_timeline(d, getter):
    """组合过滤 + 游标分段读取。返回响应 dict。

    游标与创建时过滤条件签名绑定：换条件必须从头开查；
    游标不存在（已清理/伪造）或超过 TTL → 410 cursor_expired。
    """
    limit_raw = getter("limit")
    limit = DEFAULT_LIMIT
    if limit_raw:
        try:
            limit = int(limit_raw[0] if isinstance(limit_raw, list) else limit_raw)
        except (TypeError, ValueError):
            raise AuditError(400, "invalid_filter", f"limit 必须是整数：{limit_raw!r}")
        if not (1 <= limit <= MAX_LIMIT):
            raise AuditError(400, "invalid_filter",
                             f"limit 必须在 1..{MAX_LIMIT} 之间，收到 {limit}")

    cursor_token = getter("cursor")
    cursor_token = cursor_token[0] if isinstance(cursor_token, list) else cursor_token

    if cursor_token:
        cur = d.conn.execute("SELECT * FROM audit_cursors WHERE token=?",
                             (cursor_token,)).fetchone()
        if not cur:
            raise AuditError(410, "cursor_expired",
                             "游标不存在或已过期：请清空游标，用当前过滤条件重新从头发起查询")
        if cur["expires_at"] < time.time():
            d.conn.execute("DELETE FROM audit_cursors WHERE token=?", (cursor_token,))
            d.commit()
            raise AuditError(410, "cursor_expired",
                             f"游标已过期（TTL {int(CURSOR_TTL_SECONDS)} 秒）："
                             "请用当前过滤条件重新从头发起查询")
        where, params, norm, fh = normalize_filters(getter)
        if fh != cur["filter_hash"]:
            raise AuditError(400, "cursor_filter_mismatch",
                             "游标属于另一组过滤条件：分页过程中不得增删过滤值，"
                             "请移除游标重新开查（或恢复原过滤条件）")
        after_seq = cur["after_seq"]
        page_limit = cur["page_limit"]
    else:
        where, params, norm, fh = normalize_filters(getter)
        after_seq = None
        page_limit = limit

    total = d.conn.execute(
        f"SELECT COUNT(*) AS n FROM approval_decisions WHERE {where}", params).fetchone()["n"]
    rows, has_more = _query_rows(d, where, params, page_limit, after_seq)

    next_cursor = None
    if has_more:
        # 还有后续：颁发下一段游标（本页最后一条 seq 之后）
        token = "cur_" + secrets.token_hex(16)
        last_seq = rows[-1]["seq"]
        d.conn.execute(
            "INSERT INTO audit_cursors(token,filter_hash,after_seq,page_limit,expires_at,created_at)"
            " VALUES(?,?,?,?,?,?)",
            (token, fh, last_seq, page_limit, time.time() + CURSOR_TTL_SECONDS, time.time()))
        d.commit()
        next_cursor = token
    return {
        "filters": norm,
        "page_size": len(rows),
        "limit": page_limit,
        "total_matching": total,
        "last_seq": after_seq,
        "next_cursor": next_cursor,
        "cursor_expires_in": int(CURSOR_TTL_SECONDS),
        "fields": FIELDS,
        "decisions": rows,
    }


# ---------------------------------------------------------------- 报表截面

def _canonical_blob(rows):
    """冻结行集的规范序列化（数组顺序保留，键排序，紧凑）。"""
    return json.dumps(rows, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _snapshot_rows(d, where, params, snapshot_seq):
    p = list(params) + [snapshot_seq]
    return [render_row(r) for r in d.conn.execute(
        f"SELECT * FROM approval_decisions WHERE {where} AND seq<=?"
        " ORDER BY seq DESC", p).fetchall()]


def list_reports(d):
    return [{"id": r["id"], "filter_hash": r["filter_hash"],
             "filters": json.loads(r["filter_json"]),
             "snapshot_seq": r["snapshot_seq"], "snapshot_ts": r["snapshot_ts"],
             "created_by": r["created_by"], "idem_key": r["idem_key"],
             "row_count": r["row_count"], "sha256": r["sha256"],
             "created_at": r["created_at"]}
            for r in d.conn.execute(
                "SELECT * FROM audit_reports ORDER BY created_at DESC").fetchall()]


def create_report(d, principal, body):
    """锁定当前查询截面并物化行集。idem_key 相同的重试返回同一份报表。"""
    body = body or {}
    idem_key = body.get("idem_key")
    if idem_key is not None and not str(idem_key).strip():
        raise AuditError(400, "bad_request", "idem_key 不能为空字符串")
    if idem_key:
        old = d.conn.execute("SELECT * FROM audit_reports WHERE idem_key=?",
                             (str(idem_key),)).fetchone()
        if old:
            out = _report_meta(old)
            out["idempotent_replay"] = True
            return out

    where, params, norm, fh = normalize_filters(body)

    top = d.conn.execute("SELECT MAX(seq) AS m FROM approval_decisions").fetchone()
    snapshot_seq = top["m"] or 0
    snapshot_ts = time.time()
    rows = _snapshot_rows(d, where, params, snapshot_seq)
    digest = hashlib.sha256(_canonical_blob(rows)).hexdigest()
    # 存储保留 FIELDS 键序（渲染依赖该顺序）；规范字节块只用于哈希与完整性校验
    stored = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
    rid = "rpt_" + secrets.token_hex(10)

    d.conn.execute(
        "INSERT INTO audit_reports(id,filter_hash,filter_json,snapshot_seq,snapshot_ts,"
        "created_by,idem_key,row_count,rows_json,sha256,created_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (rid, fh, json.dumps(norm, ensure_ascii=False, sort_keys=True),
         snapshot_seq, snapshot_ts, principal["login"],
         str(idem_key) if idem_key else None, len(rows),
         stored, digest, snapshot_ts))
    d.commit()
    return _report_meta(d.conn.execute(
        "SELECT * FROM audit_reports WHERE id=?", (rid,)).fetchone())


def _report_meta(r):
    return {
        "id": r["id"],
        "filter_hash": r["filter_hash"],
        "filters": json.loads(r["filter_json"]),
        "snapshot_seq": r["snapshot_seq"],
        "snapshot_ts": r["snapshot_ts"],
        "created_by": r["created_by"],
        "idem_key": r["idem_key"],
        "row_count": r["row_count"],
        "sha256": r["sha256"],
        "created_at": r["created_at"],
        "download": {
            "json": f"/api/audit/reports/{r['id']}/content?format=json",
            "csv": f"/api/audit/reports/{r['id']}/content?format=csv",
        },
    }


def _load_locked_report(d, rid):
    r = d.conn.execute("SELECT * FROM audit_reports WHERE id=?", (rid,)).fetchone()
    if not r:
        raise AuditError(404, "not_found", f"报表 {rid} 不存在（可能从未生成或已被管理员重置）")
    rows = json.loads(r["rows_json"])
    # 完整性校验：冻结字节块哈希不符说明存储被篡改/损坏
    if hashlib.sha256(_canonical_blob(rows)).hexdigest() != r["sha256"]:
        raise AuditError(500, "snapshot_tampered",
                         f"报表 {rid} 截面校验失败：冻结内容与 SHA256 不一致，拒绝导出")
    return r, rows


def get_report_meta(d, rid):
    r, _rows = _load_locked_report(d, rid)
    return _report_meta(r)


def render_report(d, rid, fmt):
    """把同一冻结行渲染为 JSON 或 CSV（字段/顺序/明细逐字一致）。"""
    if fmt not in ("json", "csv"):
        raise AuditError(400, "bad_format", f"报表格式只能是 json 或 csv，收到 {fmt!r}")
    r, rows = _load_locked_report(d, rid)
    meta = _report_meta(r)
    if fmt == "json":
        payload = {
            "schema": SCHEMA_NAME,
            "report_id": rid,
            "filters": meta["filters"],
            "snapshot": {"seq": r["snapshot_seq"], "ts": r["snapshot_ts"]},
            "generated_at": r["created_at"],
            "row_count": len(rows),
            "sha256": r["sha256"],
            "fields": FIELDS,
            "rows": rows,
        }
        # 固定键序、无随机空白 → 任意时刻重复下载字节完全一致
        body = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False).encode("utf-8")
        return body, "application/json; charset=utf-8", f"{rid}.json"
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(FIELDS)
    for row in rows:
        w.writerow([row[k] for k in FIELDS])
    return buf.getvalue().encode("utf-8"), "text/csv; charset=utf-8", f"{rid}.csv"


# ---------------------------------------------------------------- 演示时间线

def seed_demo_decisions(d, force=False):
    """播种覆盖五种结果状态的演示审批时间线（幂等）。"""
    flag = d.get_meta("approval_demo_seeded")
    if flag and not force:
        return
    now = time.time()
    chain = [
        # 申请 1001：申请 → 批准 → 批次执行闭环
        ("REQ-EVAC-1001", now - 7200, "图调度", "", "order_submit", "submitted",
         "plan", "P-1001", {"commander": "图调度", "waves": 3, "households": 11}),
        ("REQ-EVAC-1001", now - 7140, "", "闻复核", "order_approve", "approved",
         "plan", "P-1001", {"base_revision": 12, "note": "床位/座位/无障碍复核通过"}),
        ("REQ-EVAC-1001", now - 6900, "车班老吴", "闻复核", "batch_depart", "approved",
         "batch", "B-1001-01", {"vehicle": "V1", "shelter": "S1", "wave": 1}),
        # 申请 1002：申请 → 拒绝（硬约束不满足）
        ("REQ-EVAC-1002", now - 5400, "图调度", "", "order_submit", "submitted",
         "plan", "P-1002", {"commander": "图调度", "waves": 2}),
        ("REQ-EVAC-1002", now - 5320, "", "闻复核", "order_reject", "rejected",
         "plan", "P-1002", {"reason": "S2 剩余床位不足，且宠物户被排入禁宠避难点"}),
        # 批次 2003：已批准离场申请 → 道路封闭失效
        ("REQ-B-2003", now - 3600, "车班老吴", "闻复核", "batch_depart", "submitted",
         "batch", "B-2003-02", {"vehicle": "V3", "shelter": "S1", "wave": 2}),
        ("REQ-B-2003", now - 1800, "system", "", "batch_expire", "expired",
         "batch", "B-2003-02", {"reason": "道路 r5 封闭，未出发批次撤回待重排", "road": "r5"}),
        # 批次 2004：离场执行失败
        ("REQ-B-2004", now - 1200, "车班老吴", "闻复核", "batch_depart", "submitted",
         "batch", "B-2004-01", {"vehicle": "V2", "shelter": "S3", "wave": 1}),
        ("REQ-B-2004", now - 1170, "车班老吴", "", "batch_depart", "exec_failed",
         "batch", "B-2004-01", {"reason": "车辆 V2 启动系统故障，无法出发", "vehicle": "V2"}),
    ]
    for i, (rid, ts, actor, reviewer, action, result, ttype, tref, detail) in enumerate(chain):
        # 固定防重键：即便对已有台账 force 重灌也绝不重复入账
        record_decision(
            d, action, result, rid, actor=actor, reviewer=reviewer,
            target_type=ttype, target_ref=tref, detail=detail, ts=ts,
            dedup_key=f"demo-v1-{i:02d}")
    d.set_meta("approval_demo_seeded", "1")
    d.commit()


def reset_demo(d):
    """管理员重置：清空决策/游标/报表并恢复演示时间线与身份。"""
    for t in ("approval_decisions", "audit_cursors", "audit_reports"):
        d.conn.execute(f"DELETE FROM {t}")
    d.set_meta("approval_demo_seeded", "0")
    d.commit()
    ensure_principals(d)
    seed_demo_decisions(d, force=True)
