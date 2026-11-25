#!/usr/bin/env python3
"""Replay the scan drift scenarios against a running Harbor through its REST and registry APIs.

Records tests/scan-drift/golden/<scenario>.json, or compares against them with --check.
See README.md in this directory.
"""

import argparse
import base64
import csv
import difflib
import gzip
import hashlib
from http import server as httpserver
import io
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
DRIFT = os.path.join(REPO, "src", "pkg", "scan", "postprocessors", "drift", "testdata")
SCENARIOS = os.path.join(DRIFT, "scenarios")
GOLDEN = os.path.join(HERE, "golden")
PREFIX = "scandrift-"
TRACE = bool(os.environ.get("SCAN_DRIFT_TRACE"))
EXPORT_MIME = "application/vnd.security.vulnerability.report; version=1.1"
SEVERITY_RANK = {"Unknown": 0, "None": 0, "Negligible": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
VOLATILE_KEYS = {
    "creation_time", "update_time", "push_time", "pull_time", "start_time", "end_time", "duration",
    "occur_at", "date_created", "create_time", "expires_at", "report_id", "execution_id",
}
# Lists whose order the API does not define, or that the replay assembles from concurrent events.
UNORDERED_KEYS = {
    "vulnerabilities", "artifact_digests", "dangerous_cves", "dangerous_artifacts", "vul_all", "vul_critical",
    "vul_cvss_7_10", "rows", "webhooks", "resources", "error_codes",
}
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


class HTTPError(Exception):
    def __init__(self, method, url, status, body):
        super().__init__(f"{method} {url}: {status} {body[:300]!r}")
        self.status = status
        self.body = body


def http(method, url, body=None, headers=None, auth=None, ok=(200, 201, 202, 204)):
    headers = dict(headers or {})
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
        headers.setdefault("Content-Type", "application/json")
    elif isinstance(body, str):
        body = body.encode()
    if auth:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            status, rh, data = resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        status, rh, data = e.code, e.headers, e.read()
    if TRACE:
        print(f"  {time.time() - t0:6.2f}s {status} {method} {url}", file=sys.stderr)
    if ok is not None and status not in ok:
        raise HTTPError(method, url, status, data)
    return status, rh, data


class Hooks:
    """Receives webhook payloads; containers reach it through host.docker.internal."""

    def __init__(self, port):
        self.lock = threading.Lock()
        self.events = {}
        hooks = self

        class Handler(httpserver.BaseHTTPRequestHandler):
            def do_POST(self):
                data = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                with hooks.lock:
                    hooks.events.setdefault(self.path.strip("/"), []).append(json.loads(data or b"null"))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = httpserver.ThreadingHTTPServer(("0.0.0.0", port), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def take(self, key, expected, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                if len(self.events.get(key, [])) >= expected:
                    break
            time.sleep(0.2)
        # Late duplicates would land in the next capture, so wait briefly for stragglers.
        time.sleep(0.5)
        with self.lock:
            return self.events.pop(key, [])


class Harbor:
    def __init__(self, args):
        self.core = args.core.rstrip("/")
        self.api = self.core + "/api/v2.0"
        self.auth = (args.user, args.password)

    def call(self, method, path, body=None, headers=None, ok=(200, 201, 202, 204)):
        status, rh, data = http(method, self.api + path, body, headers, self.auth, ok)
        return status, rh, (json.loads(data) if data and data[:1] in (b"{", b"[") else data)

    def get(self, path, ok=(200,)):
        return self.call("GET", path, ok=ok)[2]

    def get_all(self, path, page_size=100):
        """Every page of a list endpoint. A single page of an id-ordered list holds whichever rows
        got the lowest ids, which differs between runs and between write paths."""
        out, page = [], 1
        while True:
            sep = "&" if "?" in path else "?"
            rows = self.get(f"{path}{sep}page={page}&page_size={page_size}")
            out += rows
            if len(rows) < page_size:
                return out
            page += 1

    def token(self, repo, actions):
        q = urllib.parse.urlencode({"service": "harbor-registry", "scope": f"repository:{repo}:{actions}"})
        _, _, data = http("GET", f"{self.core}/service/token?{q}", auth=self.auth)
        return json.loads(data)["token"]

    def push_image(self, repo, tag):
        tok = {"Authorization": "Bearer " + self.token(repo, "pull,push")}
        layer = gzip.compress(os.urandom(64))
        diff = "sha256:" + hashlib.sha256(gzip.decompress(layer)).hexdigest()
        config = json.dumps({
            "architecture": "amd64", "os": "linux", "config": {"Labels": {"scan-drift": uuid.uuid4().hex}},
            "rootfs": {"type": "layers", "diff_ids": [diff]},
        }).encode()
        blobs = []
        for blob in (config, layer):
            digest = "sha256:" + hashlib.sha256(blob).hexdigest()
            _, rh, _ = http("POST", f"{self.core}/v2/{repo}/blobs/uploads/", headers=tok)
            loc = urllib.parse.urljoin(self.core + "/", rh["Location"])
            loc = re.sub(r"^https?://[^/]+", self.core, loc)
            sep = "&" if "?" in loc else "?"
            http("PUT", f"{loc}{sep}digest={digest}", blob,
                 dict(tok, **{"Content-Type": "application/octet-stream"}))
            blobs.append((digest, len(blob)))
        manifest = json.dumps({
            "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": blobs[0][0], "size": blobs[0][1]},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": blobs[1][0], "size": blobs[1][1]}],
        }).encode()
        _, rh, _ = http("PUT", f"{self.core}/v2/{repo}/manifests/{tag}", manifest,
                        dict(tok, **{"Content-Type": "application/vnd.oci.image.manifest.v1+json"}))
        return rh["Docker-Content-Digest"]

    def pull_status(self, repo, tag):
        tok = {"Authorization": "Bearer " + self.token(repo, "pull"),
               "Accept": "application/vnd.oci.image.manifest.v1+json"}
        status, _, data = http("GET", f"{self.core}/v2/{repo}/manifests/{tag}", headers=tok, ok=None)
        codes = []
        if status != 200:
            try:
                codes = sorted(e.get("code", "") for e in json.loads(data).get("errors", []))
            except ValueError:
                codes = ["<unparsable>"]
        return {"status": status, "error_codes": codes}


class Run:
    """One replay of one scenario in a fresh project."""

    def __init__(self, args, harbor, hooks, scenario):
        self.args, self.h, self.hooks, self.sc = args, harbor, hooks, scenario
        self.suffix = uuid.uuid4().hex[:8]
        self.project = f"{PREFIX}{self.suffix}"
        self.scanners = {}
        self.artifacts = {}
        self.live_artifacts = []
        self.scans_since_capture = 0
        self.lock = threading.Lock()
        self.replace = {}
        self.ids = {}

    def p(self, path):
        return f"/projects/{self.project}{path}"

    def art_path(self, art):
        return self.p(f"/repositories/{art}/artifacts/{art}")

    def run(self):
        out = {"scenario": self.sc["name"], "steps": [], "captures": []}
        try:
            self.setup()
            for st in self.sc["steps"]:
                if st["op"] == "capture":
                    out["captures"].append(self.capture(st))
                else:
                    out["steps"].append(self.step(st))
        finally:
            self.teardown()
        return normalize(out, self.replace, self.ids)

    def setup(self):
        h = self.h
        h.call("POST", "/projects", {"project_name": self.project, "metadata": {"public": "false"}})
        proj = h.get(self.p(""))
        self.project_id = proj["project_id"]
        self.replace[self.project] = "<project>"
        self.ids[("project_id", self.project_id)] = "<project-id>"
        h.call("POST", self.p("/webhook/policies"), {
            "name": "scan-drift", "enabled": True,
            "event_types": ["SCANNING_COMPLETED", "SCANNING_FAILED"],
            "targets": [{"type": "http", "address": f"{self.args.hook_host}/{self.project}",
                         "skip_cert_verify": True, "payload_format": "Default"}],
        })
        for art in sorted(collect(self.sc["steps"], "artifact")):
            digest = h.push_image(f"{self.project}/{art}", art)
            info = h.get(self.art_path(art))
            self.artifacts[art] = {"digest": digest, "id": info["id"]}
            self.replace[digest] = f"<digest:{art}>"
            self.ids[("id", info["id"])] = f"<artifact-id:{art}>"
            self.ids[("artifact_id", info["id"])] = f"<artifact-id:{art}>"
            self.live_artifacts.append(art)

    def teardown(self):
        h = self.h
        for art in list(self.live_artifacts):
            h.call("DELETE", self.p(f"/repositories/{art}"), ok=None)
        h.call("DELETE", self.p(""), ok=None)
        for s in self.scanners.values():
            h.call("DELETE", f"/scanners/{s['uuid']}", ok=None)
        restore_default_scanner(h)

    def step(self, st):
        op = st["op"]
        rec = {"op": op}
        for k in ("artifact", "scanner"):
            if st.get(k):
                rec[k] = st[k]
        if op == "register_scanner":
            rec["result"] = self.register(st["scanner"])
        elif op == "scan":
            self.set_project_scanner(st["scanner"])
            rec["result"] = self.finish_scan(self.start_scan(st))
        elif op == "concurrent":
            rec["steps"] = self.concurrent(st["steps"])
        elif op == "delete_artifact":
            s, _, body = self.h.call("DELETE", self.art_path(st["artifact"]), ok=None)
            rec["result"] = outcome(s, body)
            if s == 200:
                self.live_artifacts.remove(st["artifact"])
        elif op == "delete_scanner":
            s, _, body = self.h.call("DELETE", f"/scanners/{self.scanners[st['scanner']]['uuid']}", ok=None)
            rec["result"] = outcome(s, body)
            if s == 200:
                self.scanners[st["scanner"]]["deleted"] = True
        elif op == "cleanup":
            rec["result"] = "ok"
        else:
            raise ValueError(f"unknown op {op}")
        return rec

    def register(self, label):
        name = f"{self.project}-{label}"
        path = f"{self.suffix}-{label}"
        s, rh, body = self.h.call("POST", "/scanners", {
            "name": name, "url": f"{self.args.stub_host}/{path}", "auth": "", "use_internal_addr": False,
        }, ok=None)
        if s != 201:
            return outcome(s, body)
        reg_uuid = rh["Location"].rstrip("/").rsplit("/", 1)[-1]
        self.scanners[label] = {"uuid": reg_uuid, "name": name}
        self.replace[name] = f"<scanner:{label}>"
        self.replace[f"Stub-{path}"] = f"Stub-{label}"
        self.replace[reg_uuid] = f"<scanner-uuid:{label}>"
        return "ok"

    def live_scanners(self):
        return sorted(k for k, v in self.scanners.items() if not v.get("deleted"))

    def set_project_scanner(self, label):
        self.h.call("PUT", self.p("/scanner"), {"uuid": self.scanners[label]["uuid"]},
                    headers={"X-Is-Resource-Name": "true"})

    def overview(self, art):
        info = self.h.get(self.art_path(art) + "?with_scan_overview=true", ok=(200,))
        overviews = list((info.get("scan_overview") or {}).values())
        ov = overviews[0] if len(overviews) == 1 else {}
        return info.get("scan_overview"), (ov.get("report_id"), ov.get("start_time"), ov.get("scan_status"))

    def start_scan(self, st):
        art = st["artifact"]
        http("PUT", f"{self.args.stub}/stub/reports?" + urllib.parse.urlencode({"key": f"{self.project}/{art}:{art}"}),
             report_body(st))
        _, before = self.overview(art)
        s, _, body = self.h.call("POST", self.art_path(art) + "/scan", ok=None)
        return art, before, s, body

    def finish_scan(self, started):
        art, before, s, body = started
        if s != 202:
            return outcome(s, body)
        deadline = time.time() + self.args.scan_timeout
        while time.time() < deadline:
            _, now = self.overview(art)
            if now[2] in ("Success", "Error") and now[:2] != before[:2]:
                with self.lock:
                    self.scans_since_capture += 1
                return "ok" if now[2] == "Success" else "error"
            time.sleep(0.3)
        return "timeout"

    def concurrent(self, steps):
        scanners = {s["scanner"] for s in steps if s["op"] == "scan"}
        if len(scanners) > 1:
            raise ValueError("a concurrent group can only scan with one scanner: the project has one")
        if scanners:
            self.set_project_scanner(scanners.pop())
        scans = [s for s in steps if s["op"] == "scan"]
        started = parallel([lambda s=s: self.start_scan(s) for s in scans])
        finished = parallel([lambda x=x: self.finish_scan(x) for x in started])
        out, it = [], iter(finished)
        for s in steps:
            rec = {"op": s["op"]}
            if s["op"] == "scan":
                rec.update(artifact=s["artifact"], scanner=s["scanner"], result=next(it))
            else:
                rec.update(self.step(s))
            out.append(rec)
        return out

    def capture(self, st):
        h = self.h
        cap = {"label": st["label"], "reports": [], "security": [], "export": None, "webhooks": None}
        for scanner in self.live_scanners():
            self.set_project_scanner(scanner)
            for art in sorted(self.live_artifacts):
                s, _, vulns = h.call("GET", self.art_path(art) + "/additions/vulnerabilities", ok=None)
                ov, _ = self.overview(art)
                cap["reports"].append({
                    "artifact": art, "scanner": scanner,
                    "vulnerabilities": vulns if s == 200 else outcome(s, vulns),
                    "scan_overview": ov,
                    "pull_block": self.pull_block(art, vulns if s == 200 else None),
                })
        for scanner in self.live_scanners():
            h.call("PATCH", f"/scanners/{self.scanners[scanner]['uuid']}", {"is_default": True})
            summary = h.get("/security/summary?with_dangerous_cve=true&with_dangerous_artifact=true")
            for k in ("dangerous_artifacts", "dangerous_cves"):
                if isinstance(summary, dict) and isinstance(summary.get(k), list):
                    summary[k] = top_list(summary[k])
            sec = {"scanner": scanner, "summary": summary}
            for name, q in (("all", ""), ("critical", ",severity=Critical"), ("cvss_7_10", ",cvss_score_v3=[7.0~10.0]")):
                query = urllib.parse.urlencode({"q": f"project_id={self.project_id}{q}"})
                sec["vul_" + name] = h.get_all(f"/security/vul?{query}")
            cap["security"].append(sec)
        restore_default_scanner(h)
        cap["export"] = self.export()
        cap["webhooks"] = self.hooks.take(self.project, self.scans_since_capture, self.args.hook_timeout)
        self.scans_since_capture = 0
        return cap

    def pull_block(self, art, vulns):
        h = self.h
        repo = f"{self.project}/{art}"
        meta = {"prevent_vul": "true", "severity": "high", "reuse_sys_cve_allowlist": "false"}
        h.call("PUT", self.p(""), {"metadata": meta, "cve_allowlist": {"items": []}},
               headers={"X-Is-Resource-Name": "true"})
        res = {"blocked": h.pull_status(repo, art)}
        top = highest_cve(vulns)
        if top:
            h.call("PUT", self.p(""), {"metadata": meta, "cve_allowlist": {"items": [{"cve_id": top}]}},
                   headers={"X-Is-Resource-Name": "true"})
            res["allowlisted_cve"] = top
            res["with_allowlist"] = h.pull_status(repo, art)
            high = high_cves(vulns)
            h.call("PUT", self.p(""), {"metadata": meta, "cve_allowlist": {"items": [{"cve_id": c} for c in high]}},
                   headers={"X-Is-Resource-Name": "true"})
            res["allowlisted_high_and_critical"] = high
            res["with_allowlist_high_and_critical"] = h.pull_status(repo, art)
        h.call("PUT", self.p(""), {"metadata": {"prevent_vul": "false", "reuse_sys_cve_allowlist": "true"},
                                   "cve_allowlist": {"items": []}}, headers={"X-Is-Resource-Name": "true"})
        return res

    def export(self):
        h = self.h
        _, _, body = h.call("POST", "/export/cve", {
            "job_name": f"{self.project}-export", "projects": [self.project_id], "labels": [],
            "repositories": "**", "cveIds": "", "tags": "**",
        }, headers={"X-Scan-Data-Type": EXPORT_MIME})
        ex_id = body["id"]
        deadline = time.time() + self.args.scan_timeout
        while time.time() < deadline:
            ex = h.get(f"/export/cve/execution/{ex_id}")
            if ex.get("status") in ("Success", "Error", "Stopped"):
                break
            time.sleep(0.5)
        result = {"status": ex.get("status"), "file_present": ex.get("file_present")}
        if ex.get("status") == "Success" and ex.get("file_present"):
            _, _, data = h.call("GET", f"/export/cve/download/{ex_id}")
            text = data.decode() if isinstance(data, bytes) else json.dumps(data)
            rows = list(csv.reader(io.StringIO(text)))
            result["rows"] = [dict(zip(rows[0], r)) for r in rows[1:]] if rows else []
        return result


def restore_default_scanner(h):
    for s in h.get("/scanners"):
        if not s["name"].startswith(PREFIX):
            h.call("PATCH", f"/scanners/{s['uuid']}", {"is_default": True})
            return


def highest_cve(vulns):
    if not isinstance(vulns, dict):
        return None
    items = []
    for rep in vulns.values():
        items += (rep or {}).get("vulnerabilities") or []
    if not items:
        return None
    best = max(items, key=lambda v: (SEVERITY_RANK.get(v.get("severity"), 0),
                                     ((v.get("preferred_cvss") or {}).get("score_v3") or 0), v.get("id", "")))
    return best.get("id")


def high_cves(vulns):
    out = set()
    for rep in vulns.values():
        for v in (rep or {}).get("vulnerabilities") or []:
            if SEVERITY_RANK.get(v.get("severity"), 0) >= SEVERITY_RANK["High"]:
                out.add(v["id"])
    return sorted(out)


def outcome(status, body):
    if status in (200, 201, 202, 204):
        return "ok"
    return f"error: {status}"


def report_body(st):
    if st.get("raw_report") is not None:
        return st["raw_report"]
    if st.get("report_file"):
        with open(os.path.join(DRIFT, "reports", st["report_file"]), "rb") as f:
            return f.read()
    if st.get("report") is not None:
        return json.dumps(st["report"])
    raise ValueError(f"scan step without a report: {st}")


def collect(steps, key):
    out = set()
    for st in steps:
        if st.get(key):
            out.add(st[key])
        out |= collect(st.get("steps") or [], key)
    return out


def parallel(fns):
    results = [None] * len(fns)
    errors = []

    def run(i, fn):
        try:
            results[i] = fn()
        except Exception as e:  # noqa: BLE001 - re-raised in the caller thread
            errors.append(e)

    threads = [threading.Thread(target=run, args=(i, fn)) for i, fn in enumerate(fns)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        raise errors[0]
    return results


# Security Hub returns at most this many dangerous artifacts and CVEs.
SECURITY_HUB_LIMIT = 5
TOP_ORDERING_KEYS = ("critical_cnt", "high_cnt", "medium_cnt", "low_cnt", "cvss_score_v3", "severity")


def top_list(rows):
    """A full top list orders only by counts or score, so which of several tied rows makes the cut
    varies between runs; keep only the ordering values then, as the DB layer does."""
    if len(rows) < SECURITY_HUB_LIMIT:
        return rows
    return {"complete": False,
            "ordering_values": sorted(({k: r[k] for k in TOP_ORDERING_KEYS if k in r} for r in rows),
                                      key=lambda v: json.dumps(v, sort_keys=True))}


def normalize(value, replace, ids, key=None):
    if isinstance(value, dict):
        return {k: normalize(v, replace, ids, k) for k, v in sorted(value.items()) if k not in VOLATILE_KEYS}
    if isinstance(value, list):
        items = [normalize(v, replace, ids, key) for v in value]
        if key in UNORDERED_KEYS:
            items.sort(key=lambda v: json.dumps(v, sort_keys=True))
        return items
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int) and (key, value) in ids:
        return ids[(key, value)]
    if isinstance(value, str):
        for old in sorted(replace, key=len, reverse=True):
            value = value.replace(old, replace[old])
        value = UUID_RE.sub("<uuid>", value)
        if len(value) > 512:
            value = f"<long:{len(value)}:{hashlib.sha256(value.encode()).hexdigest()[:16]}>"
    return value


def load_scenarios(only):
    out = []
    for f in sorted(os.listdir(SCENARIOS)):
        if not f.endswith(".yaml"):
            continue
        with open(os.path.join(SCENARIOS, f)) as fh:
            sc = yaml.safe_load(fh)
        if only and not any(sc["name"].startswith(o) for o in only):
            continue
        out.append(sc)
    return out


def dump(data):
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def compare_db(only):
    """Compare the API goldens (O1 findings, O2 overview) with the DB-layer goldens of the same captures."""
    failures = 0
    for sc in load_scenarios(only):
        name = sc["name"]
        if not os.path.exists(os.path.join(GOLDEN, name + ".json")):
            print(f"{name}: no API golden, skipped")
            continue
        with open(os.path.join(GOLDEN, name + ".json")) as f:
            api = json.load(f)
        with open(os.path.join(DRIFT, "golden", name + ".json")) as f:
            db = json.load(f)
        api_caps = {c["label"]: c for c in api["captures"]}
        for dcap in db.get("captures", []):
            acap = api_caps.get(dcap["label"])
            if acap is None:
                print(f"{name} {dcap['label']}: capture missing in API golden")
                failures += 1
                continue
            api_reports = {(r["artifact"], r["scanner"]): r for r in acap["reports"]}
            for drep in dcap["reports"]:
                where = f"{name} {dcap['label']} {drep['artifact']}/{drep['scanner']}"
                dv = canon((drep.get("report") or {}).get("vulnerabilities") or [])
                arep = api_reports.get((drep["artifact"], drep["scanner"]))
                if arep is None:
                    print(f"{where}: not reachable via API (DB has {len(dv)} findings)")
                    continue
                av = []
                if isinstance(arep["vulnerabilities"], dict):
                    for rep in arep["vulnerabilities"].values():
                        av += (rep or {}).get("vulnerabilities") or []
                av = canon(av)
                problems = []
                if av != dv:
                    problems += [f"   db only : {v}" for v in dv if v not in av]
                    problems += [f"   api only: {v}" for v in av if v not in dv]
                ov = list((arep.get("scan_overview") or {}).values())
                dsum = drep.get("summary") or {}
                if ov and dsum:
                    for k in ("severity", "summary", "scan_status"):
                        if ov[0].get(k) != dsum.get(k):
                            problems.append(f"   overview {k}: api={ov[0].get(k)} db={dsum.get(k)}")
                elif bool(ov) != bool(dsum):
                    problems.append(f"   overview present: api={bool(ov)} db={bool(dsum)}")
                if problems:
                    failures += 1
                    print(f"{where}: DIFF")
                    print("\n".join(problems))
                else:
                    print(f"{where}: match ({len(av)} findings)")
    return failures


def canon(vulns):
    return sorted(json.dumps(v, sort_keys=True) for v in vulns)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="compare with the golden files instead of writing them")
    ap.add_argument("--compare-db", action="store_true", help="compare API goldens with the DB-layer goldens")
    ap.add_argument("--only", default="", help="comma separated scenario name prefixes")
    ap.add_argument("--core", default=os.environ.get("HARBOR_URL", "http://localhost:8280"))
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default=os.environ.get("HARBOR_PASSWORD", "Harbor12345"))
    ap.add_argument("--stub", default="http://localhost:18089", help="stub scanner URL as seen from this host")
    ap.add_argument("--stub-host", default="http://host.docker.internal:18089",
                    help="stub scanner URL as seen from core and jobservice")
    ap.add_argument("--hook-port", type=int, default=18090)
    ap.add_argument("--hook-host", default=None, help="webhook receiver URL as seen from jobservice")
    ap.add_argument("--scan-timeout", type=float, default=120)
    ap.add_argument("--hook-timeout", type=float, default=20)
    args = ap.parse_args()
    args.hook_host = args.hook_host or f"http://host.docker.internal:{args.hook_port}"
    only = [o for o in args.only.split(",") if o]

    if args.compare_db:
        sys.exit(1 if compare_db(only) else 0)

    harbor = Harbor(args)
    for proj in harbor.get(f"/projects?q=name%3D~{PREFIX}&page_size=100"):
        print(f"removing stale project {proj['name']}", file=sys.stderr)
        for repo in harbor.get(f"/projects/{proj['name']}/repositories?page_size=100"):
            r = repo["name"].split("/", 1)[1]
            harbor.call("DELETE", f"/projects/{proj['name']}/repositories/{r}", ok=None)
        harbor.call("DELETE", f"/projects/{proj['name']}", ok=None)
    for s in harbor.get("/scanners"):
        if s["name"].startswith(PREFIX):
            harbor.call("DELETE", f"/scanners/{s['uuid']}", ok=None)

    hooks = Hooks(args.hook_port)
    os.makedirs(GOLDEN, exist_ok=True)
    failed = []
    for sc in load_scenarios(only):
        name = sc["name"]
        t0 = time.time()
        first = dump(Run(args, harbor, hooks, sc).run())
        path = os.path.join(GOLDEN, name + ".json")
        if args.check:
            with open(path) as f:
                want = f.read()
            if want != first:
                failed.append(name)
                sys.stdout.writelines(difflib.unified_diff(
                    want.splitlines(True), first.splitlines(True), f"golden/{name}.json", f"actual/{name}.json"))
            print(f"{name}: {'ok' if want == first else 'DIFF'} ({time.time() - t0:.1f}s)", file=sys.stderr)
            continue
        second = dump(Run(args, harbor, hooks, sc).run())
        if first != second:
            failed.append(name)
            sys.stdout.writelines(difflib.unified_diff(
                first.splitlines(True), second.splitlines(True), f"run1/{name}.json", f"run2/{name}.json"))
            print(f"{name}: UNSTABLE, two runs differ; golden not written", file=sys.stderr)
            continue
        with open(path, "w") as f:
            f.write(first)
        print(f"{name}: recorded ({time.time() - t0:.1f}s)", file=sys.stderr)
    if failed:
        print("failed: " + ", ".join(failed), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
