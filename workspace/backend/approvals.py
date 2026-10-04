"""运营审计员的「审批追踪」工作台。

数据模型（只追加时间线，表见 db.py）：
  approval_events  每个申请至少一条 requested 事件，随后可追加
                   approved / rejected / invalidated / execution_failed，
                   同一 request_id 的多条事件串成可检索时间线。
  approval_reports 报表截面：创建报表时把命中事件**固化成行快照**，
                   之后新增决策只追加新 seq，绝不改写任何既有报表。

查询：
  GET /api/approvals/timeline
      操作者/复核者/动作种类(可多个)/结果状态(可多个)/起止时刻组合过滤，
      keyset 游标分段读取（游标带 HMAC 签名与 TTL，过期返回 410）。

报表（JSON / CSV 共用同一份冻结行，字段、顺序、明细完全一致）：
  POST /api/approvals/reports          按当前筛选锁定截面
  GET  /api/approvals/reports          已创建截面列表
  GET  /api/approvals/reports/{id}     截面元数据（含两种格式的校验摘要）
  GET  /api/approvals/reports/{id}/download?format=json|csv
  POST /api/approvals/reports/{id}/verify  重新计算摘要并比对，进程重启后仍可校验

权限：
  Authorization: Bearer <token> 或 X-Audit-Token；用户与角色见 EVAC_AUDIT_USERS。
  audit:read  观察审批时间线、创建/下载/校验报表
  audit:write 追加审批事件（申请/批准/拒绝/失效/执行失败）
"""
import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import time
import urllib.parse
import uuid

# ---------------------------------------------------------------- 演示时间线

def seed_demo(d):
    """首次启动播种一条覆盖五种结果的演示审批时间线（幂等：已有事件则跳过）。

    时间戳相对当前时刻回退，保证起止时刻过滤、时间线排序有可见数据。
    """
    if d.conn.execute("SELECT COUNT(*) AS c FROM approval_events").fetchone()["c"]:
        return
    now = time.time()
    H = 3600

    def ev(hours_ago, request_id, action, result, operator, reviewer, subject, detail):
        d.conn.execute(
            "INSERT INTO approval_events(ts,request_id,action,result,operator,"
            "reviewer,subject,detail) VALUES(?,?,?,?,?,?,?,?)",
            (now - hours_ago * H, request_id, action, result, operator,
             reviewer, subject,
             json.dumps(detail, ensure_ascii=False, sort_keys=True,
                        separators=(",", ":"))))

    ev(49, "REQ-20260928-01", "evacuation_order", "requested", "周调度", "",
       "ORDER-第3波/G3", {"waves": 3, "households": 11, "plan": "云顶村南全量撤离"})
    ev(48.8, "REQ-20260928-01", "evacuation_order", "approved", "周调度", "李观察",
       "ORDER-第3波/G3", {"base_revision": 12, "conditions": ["S1床位核验通过"]})
    ev(48.2, "REQ-20260928-01", "evacuation_order", "execution_failed", "周调度",
       "system", "BATCH-V2-07", {"reason": "车辆 V2 出发前故障", "released_households": 5})
    ev(47.9, "REQ-20260928-01", "evacuation_order", "approved", "周调度", "林审计",
       "BATCH-V1-07", {"note": "改派 V1 后重新核准"})

    ev(30, "REQ-20261001-02", "resource_change", "requested", "吴调度", "",
       "road:r5", {"change": "close", "cause": "火线逼近 r5 沿线"})
    ev(29.7, "REQ-20261001-02", "resource_change", "rejected", "吴调度", "李观察",
       "road:r5", {"reason": "r5 是 G3 唯一撤离通道，封闭将导致 4 户无路可走"})

    ev(26, "REQ-20261002-03", "shelter_access", "requested", "郑站长", "",
       "S4", {"change": "resume", "beds": 20})
    ev(25.8, "REQ-20261002-03", "shelter_access", "approved", "郑站长", "林审计",
       "S4", {"inspection": "消防与供水复核通过"})
    ev(10, "REQ-20261002-03", "shelter_access", "invalidated", "system", "system",
       "S4", {"reason": "S4 周边二次火情，暂停接收决定自动失效", "rule": "fire_proximity"})

    ev(8, "REQ-20261003-04", "vehicle_dispatch", "requested", "吴调度", "",
       "V4", {"grid": "G5", "households": ["H08", "H09"], "needs": ["accessible"]})
    ev(7.8, "REQ-20261003-04", "vehicle_dispatch", "approved", "吴调度", "李观察",
       "V4", {"wheelchair_seats": 2})

    ev(5, "REQ-20261004-05", "relief_resource", "requested", "郑站长", "",
       "S3-beds", {"change": "add", "beds": 40, "source": "县级物资库"})
    ev(4.7, "REQ-20261004-05", "relief_resource", "rejected", "郑站长", "林审计",
       "S3-beds", {"reason": "物资库床位已被 G6 北岸预案预占，无空余配额"})

    ev(2, "REQ-20261004-06", "evacuation_order", "requested", "周调度", "",
       "ORDER-G6/第1波", {"waves": 1, "households": 2})
    d.commit()


# ---------------------------------------------------------------- 领域枚举

ACTIONS = ("evacuation_order", "resource_change", "shelter_access",
           "vehicle_dispatch", "relief_resource")
RESULTS = ("requested", "approved", "rejected", "invalidated", "execution_failed")

# 结果状态的合法后继（仅做一致性校验，不强制每个申请都走完全流程）
RESULT_NEXT = {
    "requested": ("approved", "rejected", "invalidated", "execution_failed"),
    "approved": ("invalidated", "execution_failed", "rejected"),
    "rejected": (),
    "invalidated": (),
    # 执行失败后可重新批准重试；续接必须复用同一 request_id，不允许再开 requested
    "execution_failed": ("approved", "rejected", "invalidated"),
}

DEFAULT_LIMIT = 100
MAX_LIMIT = 500
CURSOR_TTL = int(os.environ.get("EVAC_CURSOR_TTL", "300"))  # 秒；游标有效期

# 报表列（顺序即契约，JSON 与 CSV 必须一致；新增列只能追加在末尾）
REPORT_COLUMNS = ["seq", "timestamp", "request_id", "action", "result",
                  "operator", "reviewer", "subject", "detail"]

# ---------------------------------------------------------------- 错误


class ApprovalError(Exception):
    """携带 HTTP 状态码与机器可读错误码的审批模块错误。"""
    def __init__(self, status, code, message, extra=None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.extra = extra or {}


# ---------------------------------------------------------------- 身份与权限

# 默认演示账号（生产请用 EVAC_AUDIT_USERS 覆盖）：
#   token=用户名，角色冒号分隔；audit_admin 同时拥有读写，auditor 只读，
#   operator 只写（无观察权限，用于演示 403），observer 只读。
DEFAULT_USERS = {
    "audit-admin":  ("林审计", ["audit:read", "audit:write"]),
    "auditor-li":   ("李观察", ["audit:read"]),
    "operator-wu":  ("吴调度", ["audit:write"]),
    "observer-zou": ("邹巡查", ["audit:read"]),
}


def _load_users():
    raw = os.environ.get("EVAC_AUDIT_USERS", "").strip()
    if not raw:
        return DEFAULT_USERS
    users = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        parts = item.split(":")
        if len(parts) < 3:
            continue
        token, name, roles = parts[0].strip(), parts[1].strip(), parts[2].strip()
        users[token] = (name, [r.strip() for r in roles.split("|") if r.strip()])
    return users or DEFAULT_USERS


USERS = _load_users()


def authenticate(headers):
    """从 Authorization: Bearer 或 X-Audit-Token 解析调用者。失败 → 401。"""
    token = ""
    auth = headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
    if not token:
        token = headers.get("X-Audit-Token", "").strip()
    if not token:
        raise ApprovalError(401, "unauthorized",
                            "审批追踪工作台需要观察权限：请通过 Authorization: Bearer "
                            "<令牌> 或 X-Audit-Token 头提供审计令牌")
    user = USERS.get(token)
    if not user:
        raise ApprovalError(401, "unauthorized", "令牌无效或已注销，请使用有效审计令牌")
    return {"token": token, "name": user[0], "roles": user[1]}


def require(headers, scope):
    user = authenticate(headers)
    if scope not in user["roles"]:
        raise ApprovalError(
            403, "forbidden",
            f"用户 {user['name']} 缺少 {scope} 权限：{'可观察但不可写入' if scope == 'audit:write' else '没有审批追踪观察权限'}",
            {"required_scope": scope, "roles": user["roles"]})
    return user


# ---------------------------------------------------------------- 签名密钥（持久化，重启后游标/校验仍有效）

def _signing_secret(d):
    secret = d.get_meta("approval_signing_secret")
    if not secret:
        secret = secrets.token_hex(32)
        d.set_meta("approval_signing_secret", secret)
    return secret.encode("utf-8")


def _sign(d, payload):
    return hmac.new(_signing_secret(d), payload.encode("utf-8"),
                    hashlib.sha256).hexdigest()


# ---------------------------------------------------------------- 时间解析

def parse_ts(value, field):
    """支持 epoch 秒（数字）与 ISO 8601；非法值抛 invalid_filter。"""
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip()
    try:
        return float(s)
    except ValueError:
        pass
    try:
        # 兼容末尾 Z（UTC）
        from datetime import datetime
        v = s.replace("Z", "+00:00")
        return datetime.fromisoformat(v).timestamp()
    except ValueError:
        raise ApprovalError(400, "invalid_filter",
                            f"过滤值不合法：{field} 既不是 epoch 秒也不是 ISO 8601 时间：{value!r}")


# ---------------------------------------------------------------- 筛选条件

def parse_filters(qs, require_cursor_match=False, cursor_filters=None):
    """从查询参数解析筛选条件；action/result 支持逗号分隔的多值。

    返回 dict：operator, reviewer, actions[], results[], start, end
    """
    def one(name):
        v = qs.get(name, [""])[0].strip()
        return v or None

    filters = {
        "operator": one("operator"),
        "reviewer": one("reviewer"),
        "actions": [],
        "results": [],
        "start": None,
        "end": None,
    }

    raw_actions = one("action") or one("actions")
    if raw_actions:
        acts = [a.strip() for a in raw_actions.split(",") if a.strip()]
        bad = [a for a in acts if a not in ACTIONS]
        if bad:
            raise ApprovalError(400, "invalid_filter",
                                f"过滤值不合法：动作种类 {bad[0]} 不在允许集合 "
                                f"{', '.join(ACTIONS)} 内",
                                {"allowed": list(ACTIONS), "field": "action"})
        filters["actions"] = acts

    raw_results = one("result") or one("results") or one("status")
    if raw_results:
        rs = [r.strip() for r in raw_results.split(",") if r.strip()]
        bad = [r for r in rs if r not in RESULTS]
        if bad:
            raise ApprovalError(400, "invalid_filter",
                                f"过滤值不合法：结果状态 {bad[0]} 不在允许集合 "
                                f"{', '.join(RESULTS)} 内",
                                {"allowed": list(RESULTS), "field": "result"})
        filters["results"] = rs

    if qs.get("start", [""])[0].strip():
        filters["start"] = parse_ts(qs["start"][0], "start")
    if qs.get("end", [""])[0].strip():
        filters["end"] = parse_ts(qs["end"][0], "end")
    if filters["start"] is not None and filters["end"] is not None \
            and filters["start"] > filters["end"]:
        raise ApprovalError(400, "invalid_filter",
                            f"过滤值不合法：起始时刻 {filters['start']} 晚于截止时刻 "
                            f"{filters['end']}", {"field": "time_range"})

    def limit_int():
        v = one("limit")
        if v is None:
            return DEFAULT_LIMIT
        try:
            n = int(v)
        except ValueError:
            raise ApprovalError(400, "invalid_filter",
                                f"过滤值不合法：limit 必须是 1..{MAX_LIMIT} 的整数")
        if n < 1 or n > MAX_LIMIT:
            raise ApprovalError(400, "invalid_filter",
                                f"过滤值不合法：limit 必须在 1..{MAX_LIMIT} 之间，当前 {n}")
        return n

    filters["limit"] = limit_int()

    if require_cursor_match and cursor_filters is not None:
        sig_now = _filter_signature({k: filters[k] for k in
                                     ("operator", "reviewer", "actions",
                                      "results", "start", "end")})
        if sig_now != cursor_filters:
            raise ApprovalError(400, "cursor_filter_mismatch",
                                "游标与当前过滤条件不一致：翻页必须沿用首页请求的"
                                "操作者/复核者/动作/结果/时间范围，如需变更请回到第一页")
    return filters


def _where(filters):
    clauses, params = [], []
    if filters["operator"]:
        clauses.append("operator=?")
        params.append(filters["operator"])
    if filters["reviewer"]:
        clauses.append("reviewer=?")
        params.append(filters["reviewer"])
    if filters["actions"]:
        clauses.append("action IN (%s)" % ",".join("?" * len(filters["actions"])))
        params.extend(filters["actions"])
    if filters["results"]:
        clauses.append("result IN (%s)" % ",".join("?" * len(filters["results"])))
        params.extend(filters["results"])
    if filters["start"] is not None:
        clauses.append("ts>=?")
        params.append(filters["start"])
    if filters["end"] is not None:
        clauses.append("ts<=?")
        params.append(filters["end"])
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def _filter_signature(f):
    """筛选条件的稳定指纹（写入游标，翻页时核对过滤是否被改动）。"""
    canon = json.dumps(f, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------- 游标（签名 + TTL）

def make_cursor(d, filters, last_seq):
    body = {"s": last_seq, "f": _filter_signature(filters),
            "exp": int(time.time()) + CURSOR_TTL}
    payload = json.dumps(body, separators=(",", ":"))
    q = urllib.parse.quote(payload, safe="")
    sig = _sign(d, payload)
    return f"{q}.{sig}"


def decode_cursor(d, token):
    """校验游标签名/有效期；返回 (last_seq, filter_signature)。

    签名被篡改或格式错误 → cursor_invalid（400）；
    超过 TTL → cursor_expired（410）。
    """
    raw = str(token or "")
    if "." not in raw:
        raise ApprovalError(400, "cursor_invalid", "游标格式不合法：缺少签名段")
    q, sig = raw.rsplit(".", 1)
    try:
        payload = urllib.parse.unquote(q)
    except Exception:
        raise ApprovalError(400, "cursor_invalid", "游标格式不合法：无法解码")
    expected = _sign(d, payload)
    if not hmac.compare_digest(sig, expected):
        raise ApprovalError(400, "cursor_invalid",
                            "游标签名校验失败：游标可能被篡改，请从第一页重新读取")
    try:
        body = json.loads(payload)
        last_seq, fsig, exp = int(body["s"]), body["f"], int(body["exp"])
    except Exception:
        raise ApprovalError(400, "cursor_invalid", "游标内容不合法")
    if time.time() > exp:
        raise ApprovalError(410, "cursor_expired",
                            f"游标已过期（有效期 {CURSOR_TTL} 秒）：审批时间线可能已新增决策，"
                            "请丢弃该游标并从第一页重新读取")
    return last_seq, fsig


# ---------------------------------------------------------------- 行序列化（JSON/CSV 同源）

def _iso(ts):
    """毫秒精度的 UTC ISO 8601（两种报表格式共用，保证逐字节稳定）。"""
    from datetime import datetime, timezone
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.") + f"{int(round(float(ts) * 1000)) % 1000:03d}Z"


def _row(r):
    """approval_events 行 → 报表行（列顺序严格等于 REPORT_COLUMNS）。"""
    detail = r["detail"] or ""
    # detail 入库即 JSON 文本；原样透传，保证 JSON 与 CSV 明细完全相同
    return {
        "seq": r["seq"],
        "timestamp": _iso(r["ts"]),
        "request_id": r["request_id"],
        "action": r["action"],
        "result": r["result"],
        "operator": r["operator"],
        "reviewer": r["reviewer"],
        "subject": r["subject"],
        "detail": detail,
    }


def _query_rows(d, filters):
    """按筛选读取全部命中行（报表截面用；seq 升序，时间线确定顺序）。"""
    where, params = _where(filters)
    rs = d.conn.execute(
        f"SELECT seq,ts,request_id,action,result,operator,reviewer,subject,detail"
        f" FROM approval_events{where} ORDER BY seq ASC", params).fetchall()
    return [_row(r) for r in rs]


# ---------------------------------------------------------------- 时间线查询

def query_timeline(d, qs):
    """游标分段读取审批时间线（默认按 seq 倒序：最新事件在前）。"""
    cursor_token = qs.get("cursor", [""])[0].strip()
    filters = parse_filters(qs)
    where, params = _where(filters)

    last_seq = None
    fsig = None
    if cursor_token:
        last_seq, fsig = decode_cursor(d, cursor_token)
        # 翻页必须沿用首页筛选（签名过的筛选指纹核对）
        cur_f = {k: filters[k] for k in
                 ("operator", "reviewer", "actions", "results", "start", "end")}
        if _filter_signature(cur_f) != fsig:
            raise ApprovalError(400, "cursor_filter_mismatch",
                                "游标与当前过滤条件不一致：翻页必须沿用首页请求的"
                                "操作者/复核者/动作/结果/时间范围，如需变更请回到第一页")
        where += (" AND " if where else " WHERE ") + "seq<?"
        params.append(last_seq)

    limit = filters["limit"]
    rs = d.conn.execute(
        f"SELECT seq,ts,request_id,action,result,operator,reviewer,subject,detail"
        f" FROM approval_events{where} ORDER BY seq DESC LIMIT ?",
        params + [limit + 1]).fetchall()

    has_more = len(rs) > limit
    page = [_row(r) for r in rs[:limit]]
    out = {
        "filters": {k: filters[k] for k in
                    ("operator", "reviewer", "actions", "results", "start", "end")},
        "limit": limit,
        "count": len(page),
        "has_more": has_more,
        "next_cursor": None,
        "events": page,
    }
    if has_more:
        out["next_cursor"] = make_cursor(
            d, {k: filters[k] for k in
                ("operator", "reviewer", "actions", "results", "start", "end")},
            page[-1]["seq"])
    return out


# ---------------------------------------------------------------- 写入（追加事件）

def append_event(d, body, user):
    """追加一条审批事件。requested 开新申请；其余结果挂到既有申请并校验合法性。"""
    if not isinstance(body, dict):
        raise ApprovalError(400, "malformed", "请求体必须是 JSON 对象")

    result = str(body.get("result", "")).strip()
    action = str(body.get("action", "")).strip()
    if result not in RESULTS:
        raise ApprovalError(400, "invalid_field",
                            f"结果状态 result 必须是 {', '.join(RESULTS)} 之一",
                            {"allowed": list(RESULTS), "field": "result"})
    if action not in ACTIONS:
        raise ApprovalError(400, "invalid_field",
                            f"动作种类 action 必须是 {', '.join(ACTIONS)} 之一",
                            {"allowed": list(ACTIONS), "field": "action"})

    operator = str(body.get("operator", "") or user["name"]).strip()
    reviewer = str(body.get("reviewer", "")).strip()
    subject = str(body.get("subject", "")).strip()
    request_id = str(body.get("request_id", "")).strip()
    detail = body.get("detail", {})
    ts = body.get("ts")
    ts = time.time() if ts is None else parse_ts(ts, "ts")

    # 明细统一规范化为紧凑 JSON 文本入库（空明细记 {}）
    if not isinstance(detail, (dict, list)):
        raise ApprovalError(400, "invalid_field",
                            "明细 detail 必须是 JSON 对象或数组", {"field": "detail"})
    detail_json = json.dumps(detail, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"))

    # 写入幂等：相同 idem_key 永远返回首次记录
    idem_key = body.get("idem_key")
    if idem_key:
        old = d.conn.execute(
            "SELECT seq FROM approval_events WHERE idem_key=?", (idem_key,)).fetchone()
        if old:
            row = d.conn.execute(
                "SELECT seq,ts,request_id,action,result,operator,reviewer,subject,detail"
                " FROM approval_events WHERE seq=?", (old["seq"],)).fetchone()
            out = _row(row)
            out["idempotent_replay"] = True
            return out

    if result == "requested":
        if not request_id:
            request_id = f"REQ-{uuid.uuid4().hex[:12]}"
        else:
            dup = d.conn.execute(
                "SELECT 1 FROM approval_events WHERE request_id=? AND result='requested'",
                (request_id,)).fetchone()
            if dup:
                raise ApprovalError(409, "duplicate_request",
                                    f"申请 {request_id} 已存在 requested 事件，"
                                    "请改用批准/拒绝/失效/执行失败续接该申请")
        if reviewer:
            raise ApprovalError(400, "invalid_field",
                                "申请(requested)事件由操作者发起，不应携带复核者 reviewer",
                                {"field": "reviewer"})
    else:
        if not request_id:
            raise ApprovalError(400, "invalid_field",
                                f"{result} 事件必须携带 request_id 以续接既有申请")
        prev = d.conn.execute(
            "SELECT result FROM approval_events WHERE request_id=? ORDER BY seq DESC LIMIT 1",
            (request_id,)).fetchone()
        if not prev:
            raise ApprovalError(404, "request_not_found",
                                f"申请 {request_id} 不存在：必须先记录 requested 事件")
        if result not in RESULT_NEXT.get(prev["result"], ()):
            raise ApprovalError(
                409, "illegal_transition",
                f"申请 {request_id} 当前处于 {prev['result']}，不能再记录 {result}",
                {"request_id": request_id, "current": prev["result"],
                 "attempted": result, "allowed_next": list(RESULT_NEXT.get(prev["result"], ()))})
        if not reviewer:
            # 失效可由系统触发；批准/拒绝必须有复核者留痕
            if result in ("approved", "rejected"):
                raise ApprovalError(400, "invalid_field",
                                    f"{result} 事件必须记录复核者 reviewer",
                                    {"field": "reviewer"})

    cur = d.conn.execute(
        "INSERT INTO approval_events(ts,request_id,action,result,operator,reviewer,"
        "subject,detail,idem_key) VALUES(?,?,?,?,?,?,?,?,?)",
        (ts, request_id, action, result, operator, reviewer, subject,
         detail_json, idem_key))
    d.commit()
    row = d.conn.execute(
        "SELECT seq,ts,request_id,action,result,operator,reviewer,subject,detail"
        " FROM approval_events WHERE seq=?", (cur.lastrowid,)).fetchone()
    return _row(row)


# ---------------------------------------------------------------- 报表截面（冻结）

def create_report(d, body, user):
    """按当前筛选条件执行查询并把结果**固化**为不可变截面。

    幂等：相同 idem_key 返回同一报表；同条件重复点击下载应拿到同一份文件——
    前端/调用方可为一次"锁定截面"操作固定 idem_key。
    """
    body = body or {}
    idem_key = str(body.get("idem_key", "")).strip()
    if idem_key:
        old = d.conn.execute(
            "SELECT id FROM approval_reports WHERE json_extract(filters,'$.idem_key')=?",
            (idem_key,)).fetchone()
        if old:
            return get_report(d, old["id"], replay=True)

    # 筛选条件来自请求体（与 GET 时间线同名键）
    qs = {}
    for k, v in (body.get("filters") or body).items():
        if k in ("operator", "reviewer", "action", "actions", "result",
                 "results", "status", "start", "end") and v is not None:
            qs[k] = [str(v)]
    filters = parse_filters(qs)
    f_out = {k: filters[k] for k in
             ("operator", "reviewer", "actions", "results", "start", "end")}

    cutoff = d.conn.execute("SELECT COALESCE(MAX(seq),0) AS m FROM approval_events"
                            ).fetchone()["m"]
    rows = _query_rows(d, filters)

    rid = f"RPT-{uuid.uuid4().hex[:12]}"
    stored_filters = dict(f_out)
    stored_filters["idem_key"] = idem_key or None
    rows_json = json.dumps(rows, ensure_ascii=False, sort_keys=False,
                           separators=(",", ":"))
    json_bytes, csv_bytes = render_report_bytes(rows)
    rec = {
        "id": rid,
        "created_at": time.time(),
        "created_by": user["name"],
        "filters": stored_filters,
        "cutoff_seq": cutoff,
        "columns": list(REPORT_COLUMNS),
        "row_count": len(rows),
        "sha256_json": hashlib.sha256(json_bytes).hexdigest(),
        "sha256_csv": hashlib.sha256(csv_bytes).hexdigest(),
    }
    d.conn.execute(
        "INSERT INTO approval_reports(id,created_at,created_by,filters,cutoff_seq,"
        "columns,rows_json,sha256_json,sha256_csv,row_count)"
        " VALUES(?,?,?,?,?,?,?,?,?,?)",
        (rid, rec["created_at"], rec["created_by"],
         json.dumps(stored_filters, ensure_ascii=False), cutoff,
         json.dumps(REPORT_COLUMNS, ensure_ascii=False), rows_json,
         rec["sha256_json"], rec["sha256_csv"], len(rows)))
    d.commit()
    return get_report(d, rid)


def render_report_bytes(rows):
    """由同一份冻结行生成两种格式字节（字段/顺序/明细完全相同）。

    JSON：{"schema":...,"columns":[...],"rows":[...]}，紧凑、ensure_ascii=False；
    CSV：首行列名与 JSON columns 完全一致，QUOTE_MINIMAL，\\r\\n 行分隔。
    两种渲染均为确定性函数 → 进程重启后逐字节复现，摘要可校验。
    """
    payload = {
        "schema": "evac.approval-report/v1",
        "columns": list(REPORT_COLUMNS),
        "rows": rows,
    }
    json_bytes = json.dumps(payload, ensure_ascii=False, sort_keys=False,
                            separators=(",", ":")).encode("utf-8")
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(REPORT_COLUMNS),
                       extrasaction="ignore", lineterminator="\r\n")
    w.writeheader()
    for r in rows:
        w.writerow({k: r[k] for k in REPORT_COLUMNS})
    csv_bytes = buf.getvalue().encode("utf-8")
    return json_bytes, csv_bytes


def _report_row(d, rid):
    r = d.conn.execute("SELECT * FROM approval_reports WHERE id=?", (rid,)).fetchone()
    if not r:
        raise ApprovalError(404, "report_not_found", f"报表 {rid} 不存在或已被归档清理")
    return r


def get_report(d, rid, replay=False):
    r = _report_row(d, rid)
    out = {
        "id": r["id"],
        "created_at": r["created_at"],
        "created_at_iso": _iso(r["created_at"]),
        "created_by": r["created_by"],
        "filters": json.loads(r["filters"]),
        "cutoff_seq": r["cutoff_seq"],
        "columns": json.loads(r["columns"]),
        "row_count": r["row_count"],
        "formats": {
            "json": {"url": f"/api/approvals/reports/{rid}/download?format=json",
                     "sha256": r["sha256_json"],
                     "content_type": "application/json; charset=utf-8"},
            "csv": {"url": f"/api/approvals/reports/{rid}/download?format=csv",
                    "sha256": r["sha256_csv"],
                    "content_type": "text/csv; charset=utf-8"},
        },
        "verify_url": f"/api/approvals/reports/{rid}/verify",
        "frozen": True,
    }
    if replay:
        out["idempotent_replay"] = True
    return out


def list_reports(d):
    return [get_report(d, r["id"]) for r in d.conn.execute(
        "SELECT id FROM approval_reports ORDER BY created_at DESC")]


def download_report(d, rid, fmt):
    if fmt not in ("json", "csv"):
        raise ApprovalError(400, "invalid_format",
                            "报表格式 format 只支持 json 或 csv",
                            {"allowed": ["json", "csv"]})
    r = _report_row(d, rid)
    rows = json.loads(r["rows_json"])
    json_bytes, csv_bytes = render_report_bytes(rows)
    body = json_bytes if fmt == "json" else csv_bytes
    # 服务端重新计算摘要并与冻结摘要比对（损坏/被篡改可被发现）
    digest = hashlib.sha256(body).hexdigest()
    stored = r["sha256_json"] if fmt == "json" else r["sha256_csv"]
    if not hmac.compare_digest(digest, stored):
        raise ApprovalError(500, "report_corrupt",
                            f"报表 {rid} 的 {fmt} 内容与冻结摘要不一致，文件可能已损坏")
    return body, fmt, digest, r


def verify_report(d, rid):
    """进程重启后仍可校验：重新渲染两种格式并与创建时冻结的摘要比对。"""
    r = _report_row(d, rid)
    rows = json.loads(r["rows_json"])
    json_bytes, csv_bytes = render_report_bytes(rows)
    got_json = hashlib.sha256(json_bytes).hexdigest()
    got_csv = hashlib.sha256(csv_bytes).hexdigest()
    ok_json = hmac.compare_digest(got_json, r["sha256_json"])
    ok_csv = hmac.compare_digest(got_csv, r["sha256_csv"])
    # 截面不可变保证：cutoff 之后新增的 seq 不得出现在冻结行中
    max_row_seq = max((row["seq"] for row in rows), default=0)
    return {
        "id": rid,
        "ok": ok_json and ok_csv and max_row_seq <= r["cutoff_seq"],
        "frozen": True,
        "columns_match": json.loads(r["columns"]) == list(REPORT_COLUMNS),
        "json": {"sha256_expected": r["sha256_json"], "sha256_actual": got_json,
                 "match": ok_json, "bytes": len(json_bytes)},
        "csv": {"sha256_expected": r["sha256_csv"], "sha256_actual": got_csv,
                "match": ok_csv, "bytes": len(csv_bytes)},
        "cutoff_seq": r["cutoff_seq"],
        "row_count": r["row_count"],
        "max_row_seq": max_row_seq,
        "snapshot_intact": max_row_seq <= r["cutoff_seq"],
        "same_fields_both_formats": True,
    }
