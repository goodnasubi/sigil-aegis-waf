import ipaddress
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request

from stage2_loopback import prefaces, receive_all


class Stage3Loopback(unittest.TestCase):
    def start(self, binary, **variables):
        proc = subprocess.Popen(
            [binary], env={**os.environ, **variables}, stdout=subprocess.PIPE, text=True
        )
        self.addCleanup(proc.stdout.close)
        self.addCleanup(proc.wait, 5)
        self.addCleanup(proc.terminate)
        return int(proc.stdout.readline())

    def request(self, port, preface, request):
        with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
            conn.sendall(preface + request)
            return receive_all(conn)

    def sample(self, port, resource):
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/{resource}", timeout=3) as response:
            return json.load(response)

    def eventually(self, check):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            value = check()
            if value:
                return value
            time.sleep(0.05)
        self.fail("Argus did not receive the expected records")

    def test_cidr_and_routes_with_backpressure_and_recovery(self):
        v4, v6 = prefaces(sys.argv[2])
        ip = ipaddress.IPv4Address(v4[16:20])
        mapped = v6[:16] + ipaddress.IPv6Address(f"::ffff:{ip}").packed + v6[32:]
        expiry = int(time.time()) + 3600
        table = {
            "version": "test-v1",
            "entries": [
                {"cidr": f"{ip}/32", "effect": "block", "reason": "trusted_source", "expires_at": expiry},
                {"cidr": "::/0", "effect": "record", "reason": "record_v6", "expires_at": expiry},
            ],
        }
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        collector = self.start(sys.argv[3], ARGUS_TEST_DB=f"{directory.name}/argus")
        received = []
        recovered = threading.Event()
        first = threading.Event()
        stop = threading.Event()
        proxy = socket.create_server(("127.0.0.1", 0))
        proxy.settimeout(0.1)
        self.addCleanup(proxy.close)

        def relay():
            while not stop.is_set():
                try:
                    incoming, _ = proxy.accept()
                except TimeoutError:
                    continue
                with incoming:
                    incoming.settimeout(2)
                    with incoming.makefile("rb") as stream:
                        line = stream.readline(65537)
                    if not line:
                        continue
                    first.set()
                    if not recovered.is_set():
                        recovered.wait(3)
                        continue
                    with socket.create_connection(("127.0.0.1", collector), timeout=2) as upstream:
                        upstream.sendall(line)
                        with upstream.makefile("rb") as stream:
                            ack = stream.readline()
                    received.append((line, ack))
                    try:
                        incoming.sendall(ack)
                    except OSError:
                        pass

        worker = threading.Thread(target=relay, daemon=True)
        worker.start()
        self.addCleanup(worker.join, 3)
        self.addCleanup(stop.set)
        self.addCleanup(recovered.set)

        gateway = self.start(
            sys.argv[1],
            AEGIS_PORT="0",
            AEGIS_UPSTREAM_PORT="8081",
            AEGIS_ARGUS_PORT=str(proxy.getsockname()[1]),
            AEGIS_TELEMETRY_CAPACITY="1",
            AEGIS_IP_TABLE=json.dumps(table),
            AEGIS_ROUTES=json.dumps([{"id": "verify", "path": "/auth/verify"}]),
        )
        self.assertTrue(first.wait(3))
        request = (
            b"POST /auth/verify?raw-query-secret HTTP/1.1\r\nHost: example.test\r\n"
            b"Forwarded: for=198.51.100.53\r\nX-Forwarded-For: 198.51.100.55\r\n"
            b"Authorization: header-secret\r\nContent-Length: 11\r\n\r\nbody-secret"
        )
        source_block = request.replace(b"/auth/verify?", b"/other?")
        probes = [(v4, source_block), (mapped, source_block), (v6, request)] * 2
        replies = [self.request(gateway, address, wire) for address, wire in probes]
        self.assertTrue(all(reply.startswith(b"HTTP/1.1 403 ") for reply in replies), replies)
        recovered.set()

        def dropped():
            summary = self.sample(collector, "metrics?component=sigil-aegis-waf&name=waf_telemetry_dropped_total")
            return summary.get("last", 0) >= len(replies) - 1

        self.eventually(dropped)
        self.assertTrue(self.request(gateway, v6, request).startswith(b"HTTP/1.1 403 "))

        def detected():
            for line, ack in received:
                if ack == b"OK\n" and b"record_v6" in line:
                    return json.loads(line)
            return None

        log = self.eventually(detected)
        self.assertEqual(log["fields"]["route_id"], "verify")
        self.assertEqual(log["fields"]["policy_version"], "test-v1")
        self.assertEqual(log["component"], "sigil-aegis-waf")
        self.assertEqual(log["msg"], "waf_decision")
        self.assertTrue(log["ts"].endswith("Z"))

        def requests_total():
            summary = self.sample(collector, "metrics?component=sigil-aegis-waf&name=waf_requests_total")
            return summary.get("last", 0) == len(replies) + 1

        self.eventually(requests_total)

        def decisions():
            summary = self.sample(collector, "metrics?component=sigil-aegis-waf&name=waf_decision_seconds_count")
            return summary.get("last", 0) >= 1

        self.eventually(decisions)
        for line, ack in received:
            self.assertEqual(ack, b"OK\n")
            self.assertLessEqual(len(line), 65536)
            for secret in (b"raw-query-secret", b"header-secret", b"body-secret", b"/auth/verify", str(ip).encode(), b"198.51.100."):
                self.assertNotIn(secret, line)
            sample = json.loads(line)
            if sample.get("name") == "waf_decision_seconds_bucket":
                self.assertEqual(set(sample["labels"]), {"component", "le"})
                self.assertEqual(sample["labels"]["component"], "sigil-aegis-waf")
            elif "labels" in sample:
                self.assertEqual(sample["labels"], {"component": "sigil-aegis-waf"})
            else:
                self.assertNotIn("trace_id", sample)


if __name__ == "__main__":
    unittest.main(argv=sys.argv[:1])
