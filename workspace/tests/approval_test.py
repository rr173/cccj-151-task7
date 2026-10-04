"""审批追踪工作台端到端测试：独立端口 + 临时数据库，真实 HTTP 验证。

覆盖：
  权限（401 无令牌/坏令牌、403 缺观察或写入权限）；
  五种动作/五种结果、申请状态机与非法迁移、写入幂等；
  操作者/复核者/动作/结果/起止时刻组合过滤；
  游标分页、翻页筛选一致性、签名篡改(400)、过期(410)；
  报表截面：JSON/CSV 字段与顺序逐行一致、重复下载逐字节相同、
            后来新增决策不改写截面、verify 校验、
            进程重启后旧报表仍可校验/读取；
  非法过滤值(400)、不存在报表(404)、非法格式(400)。

运行：python3 tests/approval_test.py
"""
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
PORT = "8131"
BASE = f"http://127.0.0.1:{PORT}"

ADMIN = {"Authorization": "Bearer audit-admin"}      # 读写
READER = {"Authorization": "Bearer auditor-li"}     # 只读
WRITER = {"Authorization": "Bearer operator-wu"}    # 只写
PASS, FAIL = 0, 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name} {detail}")


def req(method, path, body=None, expect=200, headers=None, raw=False):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            payload = resp.read()
            if raw or resp.status in (204, 304) or not payload:
                return resp.status, payload, dict(resp.headers)
            return resp.status, json.loads(payload), dict(resp.headers)
    except urllib.error.HTTPError as e:
        payload = e.read()
        if e.code != expect:
            raise AssertionError(f"{method} {path} 预期 {expect}，实际 {e.code}: {payload!r}")
        if raw or e.code in (204, 304) or not payload:
            return e.code, payload, dict(e.headers)
        return e.code, json.loads(payload), dict(e.headers)


def start(db_path, cursor_ttl=None):
    env = dict(os.environ, EVAC_PORT=PORT, EVAC_DB=db_path, EVAC_NO_SEED="0")
    if cursor_ttl is not None:
        env["EVAC_CURSOR_TTL"] = str(cursor_ttl)
    p = subprocess.Popen([sys.executable, os.path.join(BACKEND, "server.py")],
                         env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        try:
            urllib.request.urlopen(BASE + "/api/state", timeout=2)
            return p
        except Exception:
            time.sleep(0.15)
    raise RuntimeError("服务启动失败")


def add_event(result, **kw):
    body = {"action": kw.pop("action", "evacuation_order"), "result": result}
    body.update(kw)
    _, ev, _ = req("POST", "/api/approvals/events", body, headers=ADMIN)
    return ev


def main():
    tmp = tempfile.mkdtemp(prefix="approval_test_")
    db_path = os.path.join(tmp, "approval.db")
    proc = start(db_path)
    rid_first = None
    try:
        print("【1】权限：无令牌/坏令牌/越权")
        code, body, _ = req("GET", "/api/approvals/timeline", expect=401)
        check("无令牌 → 401 unauthorized", code == 401 and body["code"] == "unauthorized")
        code, body, _ = req("GET", "/api/approvals/timeline", expect=401,
                            headers={"X-Audit-Token": "nobody"})
        check("坏令牌 → 401", code == 401 and body["code"] == "unauthorized")
        code, body, _ = req("GET", "/api/approvals/timeline", expect=403, headers=WRITER)
        check("只写用户观察时间线 → 403 forbidden", code == 403 and body["code"] == "forbidden")
        code, _, _ = req("POST", "/api/approvals/events",
                         {"action": "evacuation_order", "result": "requested"},
                         expect=403, headers=READER)
        check("只读用户追加事件 → 403", code == 403)
        _, tl, _ = req("GET", "/api/approvals/timeline", headers=READER)
        check("只读用户可观察时间线（含演示种子）", tl["count"] >= 5)

        print("【2】申请状态机：五种结果与非法迁移")
        ev = add_event("requested", subject="ORD-T1",
                       detail={"waves": 2, "households": 6})
        rid_first = ev["request_id"]
        check("requested 自动生成 request_id", ev["request_id"].startswith("REQ-"))
        code, body, _ = req("POST", "/api/approvals/events",
                            {"request_id": rid_first, "action": "evacuation_order",
                             "result": "requested"}, expect=409, headers=ADMIN)
        check("同申请重复 requested → 409 duplicate_request",
              body["code"] == "duplicate_request")
        code, body, _ = req("POST", "/api/approvals/events",
                            {"request_id": "REQ-NOSUCH", "action": "evacuation_order",
                             "result": "approved", "reviewer": "林审计"},
                            expect=404, headers=ADMIN)
        check("批准不存在申请 → 404 request_not_found", body["code"] == "request_not_found")
        code, body, _ = req("POST", "/api/approvals/events",
                            {"request_id": rid_first, "action": "evacuation_order",
                             "result": "approved"}, expect=400, headers=ADMIN)
        check("批准缺复核者 → 400", body["code"] == "invalid_field")
        add_event("approved", request_id=rid_first, reviewer="李观察",
                  subject="ORD-T1", detail={"conditions": ["ok"]})
        add_event("execution_failed", request_id=rid_first, reviewer="system",
                  subject="ORD-T1", detail={"reason": "车辆故障"})
        code, body, _ = req("POST", "/api/approvals/events",
                            {"request_id": rid_first, "action": "evacuation_order",
                             "result": "requested"}, expect=409, headers=ADMIN)
        check("execution_failed 之后不能重开 requested → 409",
              code == 409 and body["code"] in ("illegal_transition", "duplicate_request"))
        add_event("approved", request_id=rid_first, reviewer="林审计",
                  subject="ORD-T1", detail={"note": "重试核准"})

        # rejected / invalidated 终态
        rj = add_event("requested", action="resource_change", subject="road:r9")
        add_event("rejected", request_id=rj["request_id"], action="resource_change",
                  reviewer="李观察", subject="road:r9", detail={"reason": "封路阻断撤离"})
        code, body, _ = req("POST", "/api/approvals/events",
                            {"request_id": rj["request_id"], "action": "resource_change",
                             "result": "invalidated"}, expect=409, headers=ADMIN)
        check("rejected 为终态再写 invalidated → 409", body["code"] == "illegal_transition")
        inv = add_event("requested", action="shelter_access", subject="S4")
        add_event("approved", request_id=inv["request_id"], action="shelter_access",
                  reviewer="林审计", subject="S4")
        add_event("invalidated", request_id=inv["request_id"], action="shelter_access",
                  reviewer="system", subject="S4", detail={"reason": "二次火情"})

        code, body, _ = req("POST", "/api/approvals/events",
                            {"action": "bogus", "result": "requested"},
                            expect=400, headers=ADMIN)
        check("非法动作种类 → 400", body["code"] == "invalid_field")
        code, body, _ = req("POST", "/api/approvals/events",
                            {"action": "relief_resource", "result": "bogus"},
                            expect=400, headers=ADMIN)
        check("非法结果状态 → 400", body["code"] == "invalid_field")

        print("【3】写入幂等")
        a = add_event("requested", action="vehicle_dispatch", subject="V9",
                      idem_key="idem-t1")
        b = add_event("requested", action="vehicle_dispatch", subject="V9",
                      idem_key="idem-t1")
        check("相同 idem_key 返回首次记录", a["seq"] == b["seq"]
              and b.get("idempotent_replay") is True)

        print("【4】组合过滤")
        _, only_failed, _ = req(
            "GET", "/api/approvals/timeline?result=execution_failed", headers=READER)
        check("按结果过滤", all(e["result"] == "execution_failed"
                                for e in only_failed["events"])
              and only_failed["count"] >= 1)
        _, comb, _ = req(
            "GET", "/api/approvals/timeline?action=evacuation_order"
            "&result=execution_failed&reviewer=system&limit=50", headers=READER)
        check("动作+结果+复核者组合", all(
            e["action"] == "evacuation_order" and e["result"] == "execution_failed"
            and e["reviewer"] == "system" for e in comb["events"]))
        _, multi, _ = req("GET", "/api/approvals/timeline"
                          "?action=resource_change,shelter_access&limit=50", headers=READER)
        check("动作种类多值过滤", {e["action"] for e in multi["events"]}
              <= {"resource_change", "shelter_access"} and multi["count"] >= 3)
        now = time.time()
        _, win, _ = req(
            "GET", f"/api/approvals/timeline?start={now - 99999}"
            f"&end={now - 3600}&limit=500", headers=READER)
        check("起止时刻窗口（只含旧种子，不含刚写入）",
              win["count"] >= 1 and all(e["request_id"] != rid_first
                                        for e in win["events"]))
        code, body, _ = req("GET", "/api/approvals/timeline?action=hack",
                            expect=400, headers=READER)
        check("非法动作过滤值 → 400 invalid_filter", body["code"] == "invalid_filter")
        code, body, _ = req("GET", "/api/approvals/timeline?result=hack",
                            expect=400, headers=READER)
        check("非法结果过滤值 → 400", body["code"] == "invalid_filter")
        code, body, _ = req("GET", "/api/approvals/timeline?start=nope",
                            expect=400, headers=READER)
        check("非法起始时刻 → 400", body["code"] == "invalid_filter")
        code, body, _ = req("GET", "/api/approvals/timeline?limit=99999",
                            expect=400, headers=READER)
        check("limit 超上限 → 400", body["code"] == "invalid_filter")
        code, body, _ = req(
            "GET", f"/api/approvals/timeline?start={now}&end={now - 100}",
            expect=400, headers=READER)
        check("起始晚于截止 → 400", body["code"] == "invalid_filter")

        print("【5】游标分段读取")
        _, p1, _ = req("GET", "/api/approvals/timeline?limit=5", headers=READER)
        check("首页 has_more 且给出 next_cursor",
              p1["has_more"] and bool(p1["next_cursor"]))
        s1 = [e["seq"] for e in p1["events"]]
        cur = p1["next_cursor"]
        seen, pages = set(s1), 1
        last = s1
        while cur:
            from urllib.parse import quote
            _, pg, _ = req("GET", f"/api/approvals/timeline?limit=5&cursor={quote(cur)}",
                           headers=READER)
            pages += 1
            ss = [e["seq"] for e in pg["events"]]
            assert all(a > b for a, b in zip(last, ss)), "分页必须严格递减"
            assert not (seen & set(ss)), "分页不得重复"
            seen |= set(ss)
            last = ss
            cur = pg["next_cursor"]
        check(f"游标翻完全部页面（{pages} 页，{len(seen)} 条，无重复无乱序）", pages >= 2)
        # 翻页改动过滤条件 → 400
        code, body, _ = req(
            "GET", f"/api/approvals/timeline?limit=5&action=shelter_access"
            f"&cursor={quote(p1['next_cursor'])}", expect=400, headers=READER)
        check("翻页改动过滤条件 → 400 cursor_filter_mismatch",
              body["code"] == "cursor_filter_mismatch")
        # 篡改游标 → 400
        code, body, _ = req("GET", "/api/approvals/timeline?cursor=aaa.bbb",
                            expect=400, headers=READER)
        check("篡改游标 → 400 cursor_invalid", body["code"] == "cursor_invalid")

        print("【6】报表截面：字段一致 / 重复下载同一份 / 后来决策不改写")
        rbody = {"filters": {"action": "evacuation_order"}, "idem_key": "rpt-lock-1"}
        _, rpt, _ = req("POST", "/api/approvals/reports", rbody, expect=201,
                        headers=READER)
        report_id, n0, cols = rpt["id"], rpt["row_count"], rpt["columns"]
        check("报表创建返回双格式摘要",
              len(rpt["formats"]["json"]["sha256"]) == 64
              and len(rpt["formats"]["csv"]["sha256"]) == 64)
        # 幂等创建
        _, rpt2, _ = req("POST", "/api/approvals/reports", rbody, expect=201,
                         headers=READER)
        check("同 idem_key 重复锁定返回同一报表",
              rpt2["id"] == report_id and rpt2.get("idempotent_replay") is True)

        _, jbytes, jh = req("GET", f"/api/approvals/reports/{report_id}/download?format=json",
                            headers=READER, raw=True)
        _, cbytes, ch = req("GET", f"/api/approvals/reports/{report_id}/download?format=csv",
                            headers=READER, raw=True)
        j = json.loads(jbytes)
        import csv as csvmod
        import io
        cr = list(csvmod.reader(io.StringIO(cbytes.decode("utf-8"))))
        check("CSV 表头与 JSON columns 完全一致且同序", cr[0] == cols == j["columns"])
        check("行数一致", len(j["rows"]) == len(cr) - 1 == n0)
        parity = all([str(r[c]) for c in cols] == row
                     for r, row in zip(j["rows"], cr[1:]))
        check("两格式每行字段、顺序、明细完全相同", parity)

        # 重复下载 → 逐字节同一份文件（ETag / Content-SHA256）
        _, jbytes_b, jh_b = req(
            "GET", f"/api/approvals/reports/{report_id}/download?format=json",
            headers=READER, raw=True)
        check("重复下载 JSON 逐字节一致", jbytes == jbytes_b
              and jh["ETag"] == jh_b["ETag"]
              and jh["Content-SHA256"] == jh_b["Content-SHA256"])
        etag = ch["ETag"]
        code, _, _ = req(
            "GET", f"/api/approvals/reports/{report_id}/download?format=csv",
            expect=304, headers={**READER, "If-None-Match": etag})
        check("携带 ETag 条件请求 → 304（同一份文件不重复下发）", code == 304)

        # 截面之后再新增**同样命中**的审批决策
        late = add_event("requested", subject="LATE-ORDER",
                         detail={"after": "snapshot"})
        add_event("approved", request_id=late["request_id"], reviewer="林审计",
                  subject="LATE-ORDER")
        _, meta, _ = req("GET", f"/api/approvals/reports/{report_id}", headers=READER)
        _, jbytes_after, _ = req(
            "GET", f"/api/approvals/reports/{report_id}/download?format=json",
            headers=READER, raw=True)
        check("截面后新增的命中决策不改写先前报表（行数与字节不变）",
              meta["row_count"] == n0 and jbytes_after == jbytes)

        # verify
        _, ver, _ = req("POST", f"/api/approvals/reports/{report_id}/verify",
                        headers=READER)
        check("报表 verify 通过（JSON+CSV 摘要一致、截面完整、双格式字段相同）",
              ver["ok"] and ver["json"]["match"] and ver["csv"]["match"]
              and ver["columns_match"] and ver["snapshot_intact"])

        code, body, _ = req("GET", "/api/approvals/reports/RPT-NON/download?format=json",
                            expect=404, headers=READER)
        check("下载不存在报表 → 404", body["code"] == "report_not_found")
        code, body, _ = req("GET", f"/api/approvals/reports/{report_id}/download?format=xml",
                            expect=400, headers=READER)
        check("非法格式 → 400 invalid_format", body["code"] == "invalid_format")
        code, body, _ = req("POST", "/api/approvals/reports",
                            {"filters": {"action": "nope"}}, expect=400, headers=READER)
        check("报表锁定时过滤值非法 → 400", body["code"] == "invalid_filter")

        print("【7】进程重启：旧游标可继续（密钥持久）、旧报表可校验读取")
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)
        proc = start(db_path)
        _, ver2, _ = req("POST", f"/api/approvals/reports/{report_id}/verify",
                         headers=READER)
        check("重启后旧报表 verify 仍通过", ver2["ok"] and ver2["row_count"] == n0)
        _, cbytes2, _ = req(
            "GET", f"/api/approvals/reports/{report_id}/download?format=csv",
            headers=READER, raw=True)
        check("重启后 CSV 逐字节一致", cbytes2 == cbytes)
        _, tl_after, _ = req("GET", "/api/approvals/timeline?limit=1", headers=READER)
        check("重启后新写入的审批事件仍在时间线",
              tl_after["events"][0]["request_id"] == late["request_id"])
        # 报表列表恢复
        _, lst, _ = req("GET", "/api/approvals/reports", headers=READER)
        check("重启后报表列表仍含旧截面",
              any(r["id"] == report_id for r in lst["reports"]))

        print("【8】游标过期 → 410（TTL=1 秒的独立实例）")
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()

    # 短 TTL 实例：造足数据使首页产生游标，等待过期后应 410
    proc = start(os.path.join(tmp, "ttl.db"), cursor_ttl=1)
    try:
        for i in range(3):
            req("POST", "/api/approvals/events",
                {"action": "relief_resource", "result": "requested",
                 "subject": f"T{i}", "idem_key": f"ttl-{i}"}, headers=ADMIN)
        _, p1, _ = req("GET", "/api/approvals/timeline?limit=1", headers=READER)
        cur = p1["next_cursor"]
        check("短 TTL 实例首页产生游标", bool(cur))
        time.sleep(1.4)
        from urllib.parse import quote
        code, body, _ = req("GET", f"/api/approvals/timeline?limit=1&cursor={quote(cur)}",
                            expect=410, headers=READER)
        check("过期游标 → 410 cursor_expired", code == 410
              and body["code"] == "cursor_expired")
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()

    print(f"\n结果：{PASS} 通过，{FAIL} 失败")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
