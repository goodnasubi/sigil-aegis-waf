import os
import socket
import subprocess
import sys
import threading
import time
import unittest

from stage2_loopback import prefaces, receive_all

OK = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"


class Origin:
    """A loopback upstream that answers every connection and keeps what it received."""

    def __init__(self):
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.listener.settimeout(0.1)
        self.received = []
        self.stop = threading.Event()
        self.worker = threading.Thread(target=self.run, daemon=True)
        self.worker.start()

    @property
    def port(self):
        return self.listener.getsockname()[1]

    def run(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except TimeoutError:
                continue
            with conn:
                conn.settimeout(2)
                data = b""
                try:
                    # The gateway sends the validated PROXY v2 preface first.
                    while len(data) < 16 or len(data) < 16 + int.from_bytes(data[14:16], "big"):
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                    data = data[16 + int.from_bytes(data[14:16], "big"):]
                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                    head, _, body = data.partition(b"\r\n\r\n")
                    length = 0
                    for field in head.split(b"\r\n")[1:]:
                        if field.lower().startswith(b"content-length:"):
                            length = int(field.split(b":", 1)[1])
                    while len(body) < length:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        body += chunk
                    self.received.append(data)
                    conn.sendall(OK)
                except OSError as error:
                    print("origin error", error, file=sys.stderr)

    def close(self):
        self.stop.set()
        self.worker.join(2)
        self.listener.close()


def with_source(preface, last):
    """Replace the IPv4 source of a PROXY v2 preface; the SSL TLV is kept."""
    return preface[:16] + bytes([10, 0, 0, last]) + preface[20:]


class Stage4Loopback(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v4, _ = prefaces(sys.argv[2])

    def setUp(self):
        self.origin = Origin()
        self.addCleanup(self.origin.close)

    def gateway(self, **variables):
        proc = subprocess.Popen(
            [sys.argv[1]],
            stdout=subprocess.PIPE,
            env={
                **os.environ,
                "AEGIS_PORT": "0",
                "AEGIS_UPSTREAM_PORT": str(self.origin.port),
                **variables,
            },
            text=True,
        )
        self.addCleanup(proc.stdout.close)
        self.addCleanup(proc.wait, 5)
        self.addCleanup(proc.terminate)
        return int(proc.stdout.readline())

    def send(self, port, data, preface=None, shutdown=True):
        with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
            client.sendall((self.v4 if preface is None else preface) + data)
            if shutdown:
                client.shutdown(socket.SHUT_WR)
            try:
                return receive_all(client)
            except ConnectionResetError:
                return b""

    def rejected(self, port, data, status):
        before = len(self.origin.received)
        reply = self.send(port, data)
        self.assertTrue(reply.startswith(f"HTTP/1.1 {status} ".encode()), reply[:80])
        self.assertIn(b"connection: close", reply)
        time.sleep(0.05)
        self.assertEqual(len(self.origin.received), before, "an uninspected request reached the upstream")

    def test_size_limits_and_framing(self):
        port = self.gateway()
        host = b"Host: example.test\r\n"
        line = b"GET /" + b"a" * (8192 - len(b"GET / HTTP/1.1")) + b" HTTP/1.1\r\n"
        self.assertEqual(len(line) - 2, 8192)
        reply = self.send(port, line + host + b"\r\n")
        self.assertTrue(reply.startswith(b"HTTP/1.1 200 "), reply[:80])
        self.rejected(port, b"GET /" + b"a" * 8192 + b" HTTP/1.1\r\n" + host + b"\r\n", 414)

        names = b"".join(b"X-%d: v\r\n" % i for i in range(98))
        reply = self.send(port, b"GET / HTTP/1.1\r\n" + host + names + b"\r\n")
        self.assertTrue(reply.startswith(b"HTTP/1.1 200 "), reply[:80])
        self.rejected(port, b"GET / HTTP/1.1\r\n" + host + b"A: b\r\n" * 100 + b"\r\n", 431)
        self.rejected(port, b"GET / HTTP/1.1\r\n" + host + b"X-Pad: " + b"p" * 16384 + b"\r\n\r\n", 431)

        body = b"x" * (1 << 20)
        head = b"POST /upload HTTP/1.1\r\n" + host + b"Content-Length: %d\r\n\r\n"
        reply = self.send(port, head % len(body) + body)
        self.assertTrue(reply.startswith(b"HTTP/1.1 200 "), reply[:80])
        self.rejected(port, head % (len(body) + 1) + b"x" * 16, 413)

        self.rejected(port, b"POST / HTTP/1.1\r\n" + host + b"Content-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n", 400)
        self.rejected(port, b"POST / HTTP/1.1\r\n" + host + b"Content-Length: 1\r\nContent-Length: 2\r\n\r\nab", 400)

    def test_upstream_limit_is_the_smaller_one(self):
        port = self.gateway(AEGIS_UPSTREAM_BODY_LIMIT="1000")
        head = b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: %d\r\n\r\n"
        reply = self.send(port, head % 1000 + b"x" * 1000)
        self.assertTrue(reply.startswith(b"HTTP/1.1 200 "), reply[:80])
        self.rejected(port, head % 1001 + b"x" * 1001, 413)

    def test_receive_deadline_answers_408(self):
        port = self.gateway(AEGIS_RECEIVE_TIMEOUT_MS="300")
        with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
            client.sendall(self.v4 + b"GET / HTTP/1.1\r\nHost: example.test\r\n")
            reply = receive_all(client)
        self.assertTrue(reply.startswith(b"HTTP/1.1 408 "), reply[:80])
        self.assertEqual(self.origin.received, [])

    def test_rate_limit_answers_429_with_retry_after(self):
        port = self.gateway(AEGIS_KEY_RATE="1", AEGIS_KEY_BURST="2")
        request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
        replies = [self.send(port, request) for _ in range(3)]
        self.assertTrue(replies[0].startswith(b"HTTP/1.1 200 "), replies[0][:80])
        self.assertTrue(replies[1].startswith(b"HTTP/1.1 200 "), replies[1][:80])
        self.assertTrue(replies[2].startswith(b"HTTP/1.1 429 "), replies[2][:80])
        self.assertIn(b"retry-after: 1\r\n", replies[2])
        self.assertEqual(len(self.origin.received), 2)
        other = self.send(port, request, preface=with_source(self.v4, 77))
        self.assertTrue(other.startswith(b"HTTP/1.1 200 "), other[:80])

    def test_node_limit_applies_to_every_source(self):
        port = self.gateway(AEGIS_NODE_RATE="1", AEGIS_NODE_BURST="1")
        request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
        first = self.send(port, request)
        second = self.send(port, request, preface=with_source(self.v4, 78))
        self.assertTrue(first.startswith(b"HTTP/1.1 200 "), first[:80])
        self.assertTrue(second.startswith(b"HTTP/1.1 429 "), second[:80])
        self.assertIn(b"retry-after: ", second)

    def test_full_table_answers_503_without_evicting_a_limited_key(self):
        port = self.gateway(AEGIS_RATE_TABLE="1", AEGIS_KEY_RATE="1", AEGIS_KEY_BURST="1")
        request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
        first = self.send(port, request)
        newcomer = self.send(port, request, preface=with_source(self.v4, 90))
        again = self.send(port, request)
        self.assertTrue(first.startswith(b"HTTP/1.1 200 "), first[:80])
        self.assertTrue(newcomer.startswith(b"HTTP/1.1 503 "), newcomer[:80])
        self.assertTrue(again.startswith(b"HTTP/1.1 429 "), again[:80])
        self.assertEqual(len(self.origin.received), 1)

    def test_rate_limit_runs_before_body_inspection(self):
        port = self.gateway(AEGIS_KEY_BURST="1", AEGIS_KEY_RATE="1")
        blocked = b"GET /?u=javascript:alert(1) HTTP/1.1\r\nHost: example.test\r\n\r\n"
        first = self.send(port, blocked)
        second = self.send(port, blocked)
        self.assertTrue(first.startswith(b"HTTP/1.1 403 "), first[:80])
        self.assertTrue(second.startswith(b"HTTP/1.1 429 "), second[:80])
        self.assertEqual(self.origin.received, [])

    def test_invalid_limits_are_rejected_at_startup(self):
        for name, value in (
            ("AEGIS_DEADLINE_MS", "11"),
            ("AEGIS_DEADLINE_MS", "0"),
            ("AEGIS_MAX_CONNECTIONS", "0"),
            ("AEGIS_MAX_CONNECTIONS", "257"),
            ("AEGIS_NODE_RATE", "0"),
            ("AEGIS_KEY_BURST", "1000001"),
            ("AEGIS_RATE_TABLE", "4097"),
            ("AEGIS_RECEIVE_TIMEOUT_MS", "60001"),
            ("AEGIS_UPSTREAM_BODY_LIMIT", "1048577"),
            ("AEGIS_UPSTREAM_BODY_LIMIT", "many"),
        ):
            with self.subTest(name=name, value=value):
                proc = subprocess.run(
                    [sys.argv[1]],
                    env={**os.environ, "AEGIS_PORT": "0", "AEGIS_UPSTREAM_PORT": "8081", name: value},
                    capture_output=True,
                    timeout=10,
                )
                # The native entry point prints the returned status; a listening gateway prints its port.
                self.assertEqual(proc.stdout.strip(), b"1")

    def test_connection_cap_holds_back_the_next_connection(self):
        port = self.gateway(AEGIS_MAX_CONNECTIONS="2")
        request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
        holders = [socket.create_connection(("127.0.0.1", port), timeout=5) for _ in range(2)]
        self.addCleanup(lambda: [holder.close() for holder in holders])
        time.sleep(0.2)
        late = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.addCleanup(late.close)
        late.sendall(self.v4 + request)
        late.settimeout(0.3)
        with self.assertRaises(TimeoutError):
            late.recv(1)
        holders[0].close()
        late.settimeout(5)
        reply = receive_all(late)
        self.assertTrue(reply.startswith(b"HTTP/1.1 200 "), reply[:80])


if __name__ == "__main__":
    unittest.main(argv=sys.argv[:1])
