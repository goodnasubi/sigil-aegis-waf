"""Stage 4 measurement for ADR 0068 decision 6.

usage: bench_stage4.py GATEWAY SHIELD_PREFACE {representative|limits} [--requests N] [--concurrency C]

The gateway reports every inspection to a loopback Argus sink as the cumulative
waf_decision_seconds histogram. The measured interval runs from the start of the
inspection (after the complete request is received) until the decision is ready
to forward or to reject; the upstream wait, the receive time and the response
time are not part of it. The p95 check is exact on the fixed bucket bounds: p95
is at most 2 ms if and only if the le=0.002 bucket holds at least 95% of the samples.
"""

import argparse
import json
import os
import platform
import socket
import socketserver
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stage2_loopback import prefaces, receive_all  # noqa: E402

OK = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"
HOST = b"Host: example.test\r\n"


class Sink(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        self.samples = {}
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), SinkHandler)


class SinkHandler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline(65537)
        if line:
            try:
                sample = json.loads(line)
            except ValueError:
                sample = {}
            name = sample.get("name", "")
            if name.startswith("waf_decision_seconds"):
                key = (name, sample.get("labels", {}).get("le"))
                with self.server.lock:
                    self.server.samples[key] = sample["value"]
        self.wfile.write(b"OK\n")


class Origin(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), OriginHandler)


class OriginHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        data = b""
        try:
            # The gateway sends the validated PROXY v2 preface first, then the request.
            while len(data) < 16 or len(data) < 16 + int.from_bytes(data[14:16], "big"):
                chunk = self.request.recv(65536)
                if not chunk:
                    return
                data += chunk
            data = data[16 + int.from_bytes(data[14:16], "big"):]
            while b"\r\n\r\n" not in data:
                chunk = self.request.recv(65536)
                if not chunk:
                    return
                data += chunk
            head, _, body = data.partition(b"\r\n\r\n")
            length = 0
            for field in head.split(b"\r\n")[1:]:
                if field.lower().startswith(b"content-length:"):
                    length = int(field.split(b":", 1)[1])
            while len(body) < length:
                chunk = self.request.recv(65536)
                if not chunk:
                    return
                body += chunk
            self.request.sendall(OK)
        except OSError:
            pass


def representative():
    """Typical requests of at most 1 KiB, benign and hostile, in a fixed order."""
    json_body = json.dumps({"user": "alice", "items": [{"sku": "A-%d" % i, "qty": i} for i in range(1, 17)]}).encode()
    cookie = b"Cookie: session=" + b"s" * 96 + b"; theme=dark\r\n"
    common = (
        HOST
        + b"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36\r\n"
        + b"Accept: text/html,application/json;q=0.9,*/*;q=0.8\r\nAccept-Language: ja,en;q=0.8\r\n"
        + b"Accept-Encoding: gzip, br\r\n"
        + cookie
    )
    return [
        b"GET / HTTP/1.1\r\n" + common + b"\r\n",
        b"GET /products?category=books&page=3&sort=price HTTP/1.1\r\n" + common + b"\r\n",
        b"POST /api/cart HTTP/1.1\r\n" + common + b"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(json_body) + json_body,
        b"GET /assets/app.js HTTP/1.1\r\n" + common + b"If-None-Match: \"abc123\"\r\n\r\n",
        b"GET /search?q=union+select+password+from+users HTTP/1.1\r\n" + common + b"\r\n",
        b"GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\n" + common + b"\r\n",
        b"GET /download?file=../../etc/passwd HTTP/1.1\r\n" + common + b"\r\n",
        b"GET /admin/users HTTP/1.1\r\n" + common + b"\r\n",
    ]


def at_limits():
    """Ordinary-looking inputs near the accepted limits (decision 6), one case per limit."""
    line_pad = 8192 - len(b"GET / HTTP/1.1")
    return {
        "request_line_8KiB": b"GET /" + b"a" * line_pad + b" HTTP/1.1\r\n" + HOST + b"\r\n",
        "headers_100": b"GET / HTTP/1.1\r\n" + HOST + b"".join(b"X-H%d: value-%d\r\n" % (i, i) for i in range(98)) + b"\r\n",
        "headers_16KiB": b"GET / HTTP/1.1\r\n" + HOST + b"".join(b"X-H%d: %s\r\n" % (i, b"v" * 250) for i in range(60)) + b"\r\n",
        "body_1MiB": b"POST /upload HTTP/1.1\r\n" + HOST + b"Content-Length: 1048576\r\n\r\n" + b"x" * (1 << 20),
        "body_64KiB": b"POST /upload HTTP/1.1\r\n" + HOST + b"Content-Length: 65536\r\n\r\n" + b"x" * (1 << 16),
    }


class Run:
    def __init__(self, gateway, preface, origin, **env):
        self.sink = Sink()
        threading.Thread(target=self.sink.serve_forever, daemon=True).start()
        self.proc = subprocess.Popen(
            [gateway],
            stdout=subprocess.PIPE,
            text=True,
            env={
                **os.environ,
                "AEGIS_PORT": "0",
                "AEGIS_UPSTREAM_PORT": str(origin.server_address[1]),
                "AEGIS_ARGUS_PORT": str(self.sink.server_address[1]),
                "AEGIS_TELEMETRY_CAPACITY": "4096",
                "AEGIS_NODE_RATE": "1000000",
                "AEGIS_NODE_BURST": "1000000",
                "AEGIS_KEY_RATE": "1000000",
                "AEGIS_KEY_BURST": "1000000",
                "AEGIS_RATE_TABLE": "4096",
                **env,
            },
        )
        self.port = int(self.proc.stdout.readline())
        self.preface = preface

    def request(self, data):
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as client:
            client.sendall(self.preface + data)
            client.shutdown(socket.SHUT_WR)
            try:
                reply = receive_all(client)
            except ConnectionResetError:
                reply = b""
        return int(reply[9:12] or 0)

    def drive(self, workload, requests, concurrency):
        statuses = {}
        counter = iter(range(requests))
        guard = threading.Lock()

        def work():
            while True:
                with guard:
                    index = next(counter, None)
                if index is None:
                    return
                status = self.request(workload[index % len(workload)])
                with guard:
                    statuses[status] = statuses.get(status, 0) + 1

        threads = [threading.Thread(target=work) for _ in range(concurrency)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return statuses

    def histogram(self, expected):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            with self.sink.lock:
                samples = dict(self.sink.samples)
            count = samples.get(("waf_decision_seconds_count", None))
            if count is not None and count >= expected:
                break
            time.sleep(0.25)
        buckets = sorted((float(le), value) for (name, le), value in samples.items() if name.endswith("_bucket") and le != "+Inf")
        return {
            "count": samples.get(("waf_decision_seconds_count", None), 0),
            "sum_seconds": samples.get(("waf_decision_seconds_sum", None), 0.0),
            "buckets": buckets,
        }

    def peak_memory_kib(self):
        with open(f"/proc/{self.proc.pid}/status") as status:
            for line in status:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1])
        return 0

    def cpu_seconds(self):
        with open(f"/proc/{self.proc.pid}/stat") as stat:
            fields = stat.read().rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")

    def stop(self):
        self.proc.terminate()
        self.proc.wait(5)
        self.proc.stdout.close()
        self.sink.shutdown()
        self.sink.server_close()


def summarize(hist):
    count = hist["count"]
    if not count:
        return {"count": 0}
    within = {f"le_{bound * 1000:g}ms": value / count for bound, value in hist["buckets"]}
    p95 = next((bound for bound, value in hist["buckets"] if value >= 0.95 * count), None)
    return {
        "count": count,
        "mean_ms": hist["sum_seconds"] / count * 1000,
        "p95_upper_bound_ms": None if p95 is None else p95 * 1000,
        "fraction_within": within,
    }


def machine():
    model = ""
    with open("/proc/cpuinfo") as info:
        for line in info:
            if line.startswith("model name"):
                model = line.split(":", 1)[1].strip()
                break
    with open("/proc/meminfo") as info:
        memory_kib = int(info.readline().split()[1])
    return {
        "cpu_model": model,
        "logical_cpus": os.cpu_count(),
        "memory_gib": round(memory_kib / 1048576, 1),
        "kernel": platform.release(),
        "python": platform.python_version(),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("gateway")
    parser.add_argument("preface")
    parser.add_argument("profile", choices=("representative", "limits"))
    parser.add_argument("--requests", type=int, default=2000)
    parser.add_argument("--concurrency", type=int, default=8)
    args = parser.parse_args()
    v4, _ = prefaces(args.preface)
    origin = Origin()
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    report = {"machine": machine(), "profile": args.profile, "concurrency": args.concurrency}
    if args.profile == "representative":
        workload = representative()
        report["request_sizes"] = [len(item) for item in workload]
        run = Run(args.gateway, v4, origin, AEGIS_MAX_CONNECTIONS=str(max(args.concurrency, 1)))
        try:
            run.request(workload[0])
            before = run.cpu_seconds()
            started = time.monotonic()
            statuses = run.drive(workload, args.requests, args.concurrency)
            report["wall_seconds"] = round(time.monotonic() - started, 2)
            report["gateway_cpu_ms_per_request"] = round((run.cpu_seconds() - before) / args.requests * 1000, 2)
            report["statuses"] = statuses
            report["decision"] = summarize(run.histogram(args.requests))
            report["peak_rss_kib"] = run.peak_memory_kib()
        finally:
            run.stop()
        report["p95_within_2ms"] = report["decision"].get("fraction_within", {}).get("le_2ms", 0) >= 0.95
    else:
        cases = {}
        for name, data in at_limits().items():
            run = Run(args.gateway, v4, origin, AEGIS_MAX_CONNECTIONS=str(max(args.concurrency, 1)))
            try:
                count = 40
                statuses = run.drive([data], count, args.concurrency)
                cases[name] = {
                    "request_bytes": len(data),
                    "statuses": statuses,
                    "decision": summarize(run.histogram(count)),
                    "peak_rss_kib": run.peak_memory_kib(),
                }
            finally:
                run.stop()
        report["cases"] = cases
    print(json.dumps(report, indent=2, sort_keys=True))
    origin.shutdown()


if __name__ == "__main__":
    main()
