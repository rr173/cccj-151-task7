"""审批追踪工作台端到端测试。

独立端口 + 临时数据库，覆盖：
  * 身份/观察权限（401/403）、过滤值非法（400 invalid_filter）；
  * 操作者/复核者/动作/结果/起止时刻组合过滤与游标分段（含游标失配 400、过期 410）；
  * 报表创建即锁定 snapshot_seq 截面，JSON/CSV 字段/顺序/明细完全相同；
  * 幂等键重复生成只取回同一份；重复下载字节一致；后来新增决策不改写旧截面；
  * 进程重启后旧报表仍可校验/读取、旧游标仍有效（TTL 内）；
  * 业务链路（发布批准、乐观并发失效、撤回失效、离场执行）自动落审批台账。

运行：python3 tests/audit_test.py
"""
import csv
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(HERE, "..", "backend")
PORT = "8096"
BASE = f"http://127.0.0.1:{PORT}"

PASS, FAIL = 0, 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name} {detail}")


def req(method, path, body=None, expect=200, user=None, token=None, raw=False):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if user:
        headers["X-Audit-User"] = user
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            payload = resp.read()
            if raw:
                return resp.status, payload, dict(resp.headers)
            return resp.status, json.loads(payload)
    except urllib.error.HTTPError as e:
        payload_body = e.read()
        if e.code != expect:
            raise AssertionError(
                f"{method} {path} 预期 {expect}，实际 {e.code}: {payload_body}")
        return e.code, json.loads(payload_body)


def content(path, expect=200, user=None):
    headers = {}
    if user:
        headers["X-Audit-User"] = user
    r = urllib.request.Request(BASE + path, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        body = e.read()
        if e.code != expect:
            raise AssertionError(f"GET {path} 预期 {expect}，实际 {e.code}: {body}")
        return e.code, body, dict(e.headers)


def start(db_path, cursor_ttl=None):
    env = dict(os.environ, EVAC_PORT=PORT, EVAC_DB=db_path, EVAC_NO_SEED="1")
    if cursor_ttl is not None:
        env["EVAC_CURSOR_TTL"] = str(cursor_ttl)
    p = subprocess.Popen([sys.executable, os.path.join(BACKEND, "server.py")],
                         env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         preexec_fn=os.setsid)
    for _ in range(60):
        try:
            req("GET", "/api/audit/principals")
            return p
        except Exception:
            time.sleep(0.15)
    raise RuntimeError("服务启动失败")


def stop(p):
    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    for _ in range(30):
        if p.poll() is not None:
            return
        time.sleep(0.1)
    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
    time.sleep(0.3)


FIELDS = ["seq", "ts", "request_id", "actor", "reviewer", "action_kind",
          "result", "target_type", "target_ref", "detail"]


def main():
    tmp = tempfile.mkdtemp(prefix="evac_audit_")
    db_path = os.path.join(tmp, "test.db")
    proc = start(db_path)

    try:
        print("【1】身份与观察权限")
        _, pr = req("GET", "/api/audit/principals")
        logins = {p["login"]: p for p in pr["principals"]}
        check("播种 4 个审计身份", len(pr["principals"]) == 4)
        check("审计/复核有观察权限，调度/车班没有",
              logins["auditor.lin"]["can_observe"]
              and logins["reviewer.wen"]["can_observe"]
              and not logins["planner.tu"]["can_observe"]
              and not logins["ops.wu"]["can_observe"])

        st, b = req("GET", "/api/audit/decisions", expect=401)
        check("无身份 → 401 unauthenticated", b.get("code") == "unauthenticated")
        st, b = req("GET", "/api/audit/decisions", expect=403, user="ghost")
        check("未知身份 → 403 unknown_principal", b.get("code") == "unknown_principal")
        st, b = req("GET", "/api/audit/decisions?result=approved",
                    expect=403, user="planner.tu")
        check("无观察权限 → 403 observe_forbidden",
              b.get("code") == "observe_forbidden")

        print("【2】过滤值合法性")
        st, b = req("GET", "/api/audit/decisions?result=bogus",
                    expect=400, user="auditor.lin")
        check("非法结果状态 → 400 invalid_filter", b.get("code") == "invalid_filter")
        st, b = req("GET", "/api/audit/decisions?action=hack",
                    expect=400, user="auditor.lin")
        check("非法动作种类 → 400 invalid_filter", b.get("code") == "invalid_filter")
        st, b = req("GET", "/api/audit/decisions?time_from=notatime",
                    expect=400, user="auditor.lin")
        check("非法时间 → 400 invalid_filter", b.get("code") == "invalid_filter")
        st, b = req("GET", "/api/audit/decisions?time_from=2&time_to=1",
                    expect=400, user="auditor.lin")
        check("起止倒置 → 400 invalid_filter", b.get("code") == "invalid_filter")
        st, b = req("GET", "/api/audit/decisions?unknown=1",
                    expect=400, user="auditor.lin")
        check("未知参数 → 400 invalid_filter", b.get("code") == "invalid_filter")
        st, b = req("GET", "/api/audit/decisions?limit=9999",
                    expect=400, user="auditor.lin")
        check("limit 超界 → 400 invalid_filter", b.get("code") == "invalid_filter")

        print("【3】组合过滤 + 游标分段")
        _, d = req("GET", "/api/audit/decisions?limit=3", user="auditor.lin")
        check("演示时间线共 9 条", d["total_matching"] == 9)
        check("字段清单固定", d["fields"] == FIELDS)
        seqs1 = [x["seq"] for x in d["decisions"]]
        cur1 = d["next_cursor"]
        check("首页 3 条按 seq 倒序", seqs1 == [9, 8, 7] and bool(cur1))

        _, d2 = req("GET", f"/api/audit/decisions?limit=3&cursor={cur1}",
                    user="auditor.lin")
        check("第二段游标续读 3 条", [x["seq"] for x in d2["decisions"]] == [6, 5, 4])
        check("继续颁发游标", bool(d2["next_cursor"]))
        _, d3 = req("GET", f"/api/audit/decisions?limit=3&cursor={d2['next_cursor']}",
                    user="auditor.lin")
        check("第三段恰好剩余", [x["seq"] for x in d3["decisions"]] == [3, 2, 1])
        check("末页不再颁发游标", d3["next_cursor"] is None)

        # 游标与过滤条件绑定：换过滤值必须重新开查
        st, b = req("GET", f"/api/audit/decisions?result=rejected&limit=3&cursor={cur1}",
                    expect=400, user="auditor.lin")
        check("游标换过滤条件 → 400 cursor_filter_mismatch",
              b.get("code") == "cursor_filter_mismatch")
        # 伪造/不存在游标
        st, b = req("GET", "/api/audit/decisions?cursor=cur_deadbeef",
                    expect=410, user="auditor.lin")
        check("未知游标 → 410 cursor_expired", b.get("code") == "cursor_expired")

        # 组合过滤：复核者 + 动作 + 结果 + 时间窗
        now = time.time()
        qs = (f"reviewer=%E9%97%BB%E5%A4%8D%E6%A0%B8&action=order_approve"
              f"&result=approved&time_from={int(now-100000)}&time_to={int(now+100000)}")
        _, df = req("GET", f"/api/audit/decisions?{qs}", user="auditor.lin")
        check("复核者+动作+结果+时间窗组合命中 1 条",
              df["total_matching"] == 1
              and df["decisions"][0]["request_id"] == "REQ-EVAC-1001")
        _, da = req("GET", "/api/audit/decisions?actor=system&result=expired",
                    user="auditor.lin")
        check("操作者 system + 失效 命中",
              da["total_matching"] == 1
              and da["decisions"][0]["request_id"] == "REQ-B-2003")
        _, dz = req("GET", f"/api/audit/decisions?time_to={now-100000}",
                    user="auditor.lin")
        check("时间窗外无记录", dz["total_matching"] == 0)

        # 时间线同一 request_id 串起五种结果
        _, dall = req("GET", "/api/audit/decisions?limit=50", user="auditor.lin")
        by_req = {}
        for x in dall["decisions"]:
            by_req.setdefault(x["request_id"], set()).add(x["result"])
        check("五种结果状态全部出现",
              {"submitted", "approved", "rejected", "expired",
               "exec_failed"} <= {x["result"] for x in dall["decisions"]})

        # 按申请编号拉出一条完整生命周期链
        _, dchain = req(
            "GET", "/api/audit/decisions?request_id=REQ-EVAC-1001&limit=20",
            user="auditor.lin")
        check("按申请编号取完整链（3 条：申请→批准→执行）",
              dchain["total_matching"] == 3
              and [x["result"] for x in dchain["decisions"]]
              == ["approved", "approved", "submitted"])

        print("【4】报表截面锁定（JSON/CSV 同字段同顺序同明细）")
        st, rep = req("POST", "/api/audit/reports",
                      {"idem_key": "k1"}, expect=201, user="auditor.lin")
        rid = rep["id"]
        check("报表创建 201，锁定 9 行截面",
              st == 201 and rep["row_count"] == 9 and rep["snapshot_seq"] == 9)
        st, jb, hj = content(
            f"/api/audit/reports/{rid}/content?format=json", user="auditor.lin")
        st2, cb, hc = content(
            f"/api/audit/reports/{rid}/content?format=csv", user="auditor.lin")
        check("两种格式 200 且 Content-Type 正确",
              "application/json" in hj["Content-Type"] and "text/csv" in hc["Content-Type"])
        jobj = json.loads(jb)
        crows = list(csv.reader(io.StringIO(cb.decode())))
        check("CSV 表头 == JSON fields（同字段同顺序）", crows[0] == jobj["fields"] == FIELDS)
        check("行数一致", len(crows) - 1 == jobj["row_count"] == 9)
        same = all(
            all(str(row[k]) == dict(zip(FIELDS, crows[i + 1]))[k] for k in FIELDS)
            for i, row in enumerate(jobj["rows"]))
        check("逐格比对：两格式明细完全相同", same)
        check("ts 为确定 UTC ISO 串", jobj["rows"][0]["ts"].endswith("Z"))

        # 重复下载字节一致
        _, jb2, _ = content(f"/api/audit/reports/{rid}/content?format=json",
                            user="auditor.lin")
        _, cb2, _ = content(f"/api/audit/reports/{rid}/content?format=csv",
                            user="auditor.lin")
        check("重复点击下载拿到同一份文件（字节级）", jb == jb2 and cb == cb2)
        check("ETag 为截面哈希", hj.get("ETag", "").strip('"') == rep["sha256"])

        # 重复生成（相同幂等键）→ 同一份
        _, rep2 = req("POST", "/api/audit/reports", {"idem_key": "k1"},
                      user="auditor.lin")
        check("同 idem_key 重放返回同一报表",
              rep2.get("idempotent_replay") and rep2["id"] == rid)

        # 截面之后新增决策 → 旧报表不变
        req("POST", "/api/audit/decisions",
            {"request_id": "REQ-LATE", "action_kind": "manual_note",
             "result": "rejected", "target_type": "other",
             "detail": {"why": "截面之后"}}, user="planner.tu")
        _, ja2, _ = content(f"/api/audit/reports/{rid}/content?format=json",
                            user="auditor.lin")
        _, ca2, _ = content(f"/api/audit/reports/{rid}/content?format=csv",
                            user="auditor.lin")
        frozen = json.loads(ja2)
        check("后来新增决策不改写先前截面（仍 9 行、字节一致）",
              ja2 == jb and ca2 == cb and frozen["row_count"] == 9
              and frozen["snapshot"]["seq"] == 9)
        # 新报表（另一幂等键）应包含新决策与更高水位
        _, rep3 = req("POST", "/api/audit/reports", {"idem_key": "k2"},
                      expect=201, user="auditor.lin")
        check("新报表看到新水位（10 行）",
              rep3["row_count"] == 10 and rep3["snapshot_seq"] == 10
              and rep3["id"] != rid)

        # 过滤截面：报表只含过滤命中行
        _, repf = req("POST", "/api/audit/reports",
                      {"idem_key": "kf", "result": ["expired"]},
                      user="auditor.lin")
        _, fb, _ = content(f"/api/audit/reports/{repf['id']}/content?format=json",
                           user="auditor.lin")
        check("过滤报表只物化命中行",
              json.loads(fb)["row_count"] == 1
              and all(r["result"] == "expired" for r in json.loads(fb)["rows"]))

        # 错误格式 / 未知报表
        st, b, _ = content(f"/api/audit/reports/{rid}/content?format=xml",
                           expect=400, user="auditor.lin")
        check("非法格式 → 400", json.loads(b).get("code") == "bad_format")
        st, b, _ = content("/api/audit/reports/rpt_nope/content?format=json",
                           expect=404, user="auditor.lin")
        check("未知报表 → 404", json.loads(b).get("code") == "not_found")
        # 下载令牌（浏览器直连场景）
        st, tb, _ = content(
            f"/api/audit/reports/{rid}/content?format=csv&token=tok-reviewer-wen")
        check("有效下载令牌可取报表", st == 200 and tb == cb)
        st, b, _ = content(
            f"/api/audit/reports/{rid}/content?format=csv&token=forged", expect=403)
        check("伪造令牌 → 403", json.loads(b).get("code") == "bad_download_token")

        # 人工录入校验
        st, b = req("POST", "/api/audit/decisions",
                    {"action_kind": "manual_note", "result": "approved"},
                    expect=400, user="planner.tu")
        check("录入缺 request_id → 400", b.get("code") == "bad_request")

        print("【5】进程重启：旧报表/游标仍可校验读取")
        stop(proc)
        proc = start(db_path)
        _, jrest, _ = content(f"/api/audit/reports/{rid}/content?format=json",
                              user="auditor.lin")
        check("重启后旧报表字节一致", jrest == jb)
        _, mrest = req("GET", f"/api/audit/reports/{rid}", user="auditor.lin")
        check("重启后报表元数据完整",
              mrest["row_count"] == 9 and mrest["sha256"] == rep["sha256"])

        # 新游标跨重启在 TTL 内有效
        _, dp = req("GET", "/api/audit/decisions?limit=2", user="auditor.lin")
        cursor = dp["next_cursor"]
        stop(proc)
        proc = start(db_path)
        _, dpn = req("GET", f"/api/audit/decisions?limit=2&cursor={cursor}",
                     user="auditor.lin")
        check("游标跨重启仍可校验续读",
              [x["seq"] for x in dpn["decisions"]] == [8, 7])

        print("【6】游标 TTL 过期")
        stop(proc)
        proc = start(db_path, cursor_ttl=0)
        # TTL=0：颁发即过期
        _, dz2 = req("GET", "/api/audit/decisions?limit=2", user="auditor.lin")
        expired_cursor = dz2["next_cursor"]
        check("TTL=0 仍颁发游标结构", bool(expired_cursor))
        st, b = req("GET",
                    f"/api/audit/decisions?limit=2&cursor={expired_cursor}",
                    expect=410, user="auditor.lin")
        check("过期游标 → 410 cursor_expired", b.get("code") == "cursor_expired")

        print("【7】业务链路自动入台账")
        stop(proc)
        proc = start(db_path)  # 恢复默认 TTL
        # 导入最小态势并完整走一遍 申请→批准→离场
        grids = [{"code": "GA", "name": "甲", "x": 0, "y": 0},
                 {"code": "GB", "name": "乙", "x": 1, "y": 0}]
        shelters = [{"code": "SA", "name": "避难A", "x": 2, "y": 0, "beds": 50}]
        roads = [{"code": "ra", "a": "GA", "b": "GB", "length": 1, "capacity": 5},
                 {"code": "rb", "a": "GB", "b": "SA", "length": 1, "capacity": 5}]
        vehicles = [{"code": "VA", "name": "车A", "seats": 20},
                    {"code": "VB", "name": "车B", "seats": 20}]
        for kind, items in (("grids", grids), ("shelters", shelters),
                            ("roads", roads), ("vehicles", vehicles)):
            req("POST", f"/api/import/{kind}", items)
        req("POST", "/api/households",
            {"ref": "HA1", "grid": "GA", "members": 3, "contact": "x"})
        _, plan = req("POST", "/api/plan",
                      {"name": "链路方案", "commander": "图调度"})
        check("规划可行", plan["feasible"])
        req("POST", f"/api/plans/{plan['id']}/publish", {"commander": "闻复核"})
        state = req("GET", "/api/state")[1]
        batch_id = next(b_["id"] for b_ in state["batches"]
                        if b_["status"] == "scheduled")
        req("POST", f"/api/batches/{batch_id}/depart", {"commander": "闻复核"})

        _, dt = req("GET", "/api/audit/decisions?limit=50", user="auditor.lin")
        pairs = {(x["request_id"], x["action_kind"], x["result"])
                 for x in dt["decisions"]}
        check("方案申请 submitted 落账",
              (plan["id"], "order_submit", "submitted") in pairs)
        check("复核发布 approved 落账",
              (plan["id"], "order_approve", "approved") in pairs)
        check("离场执行 approved 落账",
              (batch_id, "batch_depart", "approved") in pairs)

        # 乐观并发失败（方案所依据修订号已推进）→ expired
        # 先新增住户推进修订号，再让 plan_b 基于旧修订号制定，随后用 plan_c 抢先发布
        req("POST", "/api/households",
            {"ref": "HA2", "grid": "GA", "members": 2})
        _, plan_b = req("POST", "/api/plan",
                        {"name": "旧方案", "commander": "图调度"})
        _, plan_c = req("POST", "/api/plan",
                        {"name": "新方案", "commander": "图调度"})
        req("POST", f"/api/plans/{plan_c['id']}/publish", {"commander": "闻复核"})
        st, b = req("POST", f"/api/plans/{plan_b['id']}/publish",
                    {"commander": "闻复核"}, expect=409)
        _, de = req("GET",
                    "/api/audit/decisions?result=expired&limit=50",
                    user="auditor.lin")
        check("过期方案发布 → expired 落账",
              any(x["request_id"] == plan_b["id"] for x in de["decisions"]))

        # 封路导致未出发批次撤回 → expired
        state = req("GET", "/api/state")[1]
        sched = [x["id"] for x in state["batches"] if x["status"] == "scheduled"]
        req("POST", "/api/events", {"type": "road_close", "code": "rb"})
        _, dex = req("GET",
                     "/api/audit/decisions?result=expired&limit=50",
                     user="auditor.lin")
        expired_batches = {x["request_id"] for x in dex["decisions"]}
        check("撤回批次 → expired 落账",
              bool(sched) and all(s in expired_batches for s in sched))
    finally:
        stop(proc)

    print(f"\n结果：{PASS} 通过，{FAIL} 失败")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
