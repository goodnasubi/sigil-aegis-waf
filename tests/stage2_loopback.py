import os
import socket
import subprocess
import sys
import unittest


def receive_all(conn):
    chunks = []
    while chunk := conn.recv(16384):
        chunks.append(chunk)
    return b"".join(chunks)


def prefaces(binary):
    numbers = iter(map(int, subprocess.check_output([binary], text=True).splitlines()))
    return tuple(bytes(next(numbers) for _ in range(size)) for size in numbers if size)


class Loopback(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v4, cls.v6 = prefaces(sys.argv[2])
        cls.origin = socket.socket()
        cls.addClassCleanup(cls.origin.close)
        cls.origin.bind(("127.0.0.1", 0))
        cls.origin.listen()
        cls.origin.settimeout(3)
        cls.gateway = subprocess.Popen(
            [sys.argv[1]], stdout=subprocess.PIPE, text=True,
            env={
                **os.environ,
                "AEGIS_PORT": "0",
                "AEGIS_UPSTREAM_PORT": str(cls.origin.getsockname()[1]),
            },
        )
        cls.addClassCleanup(cls.gateway.stdout.close)
        cls.addClassCleanup(cls.gateway.wait, 5)
        cls.addClassCleanup(cls.gateway.terminate)
        cls.port = int(cls.gateway.stdout.readline())

    def connect(self):
        return socket.create_connection(("127.0.0.1", self.port), timeout=3)

    def assert_no_origin(self):
        self.origin.settimeout(0.05)
        try:
            with self.assertRaises(TimeoutError):
                conn, _ = self.origin.accept()
                conn.close()
        finally:
            self.origin.settimeout(3)

    def reject(self, data, status=None):
        with self.connect() as client:
            client.sendall(data)
            client.shutdown(socket.SHUT_WR)
            try:
                reply = receive_all(client)
            except ConnectionResetError:
                if status is not None:
                    raise
                reply = b""
        if status is None:
            self.assertEqual(reply, b"")
        else:
            self.assertTrue(reply.startswith(f"HTTP/1.1 {status} ".encode()), reply)
        self.assert_no_origin()

    def forward(self, preface, request, expected, remainder=b""):
        response = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"
        with self.connect() as client:
            # Separate the PROXY fixed header, address/TLV block and HTTP bytes.
            for part in (preface[:9], preface[9:16], preface[16:], request):
                client.sendall(part)
            if remainder:
                self.assert_no_origin()
                client.sendall(remainder)
            conn, _ = self.origin.accept()
            with conn:
                conn.settimeout(3)
                received = b""
                while len(received) < len(preface) + len(expected):
                    chunk = conn.recv(16384)
                    self.assertTrue(chunk)
                    received += chunk
                self.assertEqual(received, preface + expected)
                conn.sendall(response)
            self.assertEqual(receive_all(client), response)

    def test_normal_and_forwarding_header_removal(self):
        self.forward(
            self.v4,
            b"GET /hello?q=1 HTTP/1.1\r\nHost: EXAMPLE.TEST:443\r\n"
            b"Forwarded: ignored\r\nX-Forwarded-For: ignored\r\n\r\n",
            b"GET /hello?q=1 HTTP/1.1\r\nhost: EXAMPLE.TEST:443\r\nconnection: close\r\n\r\n",
        )

    def test_ipv6_chunked_body_must_be_complete(self):
        self.forward(
            self.v6,
            b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n3\r\na",
            b"POST / HTTP/1.1\r\nhost: example.test\r\ncontent-length: 3\r\nconnection: close\r\n\r\nabc",
            b"bc\r\n0\r\n\r\n",
        )

    def test_connection_tokens_are_case_insensitive(self):
        request = b"GET / HTTP/1.1\r\nHost: example.test\r\n"
        expected = b"GET / HTTP/1.1\r\nhost: example.test\r\nconnection: close\r\n\r\n"
        for token in (b"Keep-Alive", b"Close"):
            with self.subTest(token=token):
                self.forward(self.v4, request + b"Connection: " + token + b"\r\n\r\n", expected)

    def test_invalid_proxy_metadata(self):
        request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
        bad_port = self.v4[:24] + b"\x00\x00" + self.v4[26:]
        bad_tls = self.v4[:-1] + b"2"
        bad_authority = self.v4.replace(b"example.test", b"EXAMPLE.TEST")
        for prefix in (b"", self.v4[:20], bad_port, bad_tls, bad_authority):
            with self.subTest(prefix=prefix):
                self.reject(prefix + request)
        self.reject(self.v4 + self.v4 + request, 400)

    def test_short_proxy_tlv_header(self):
        request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
        for tail in (b"\x02", b"\x02\x00"):
            with self.subTest(size=len(tail)):
                payload = self.v4[16:] + tail
                preface = self.v4[:14] + len(payload).to_bytes(2, "big") + payload
                self.reject(preface + request)

    def test_http_rejections_never_connect(self):
        host = b"Host: example.test\r\n"
        cases = (
            (b"GET / HTTP/1.1\r\nHost: other.test\r\n\r\n", 421),
            (b"GET /a/../b HTTP/1.1\r\n" + host + b"\r\n", 403),
            (b"GET /auth/verify HTTP/1.1\r\n" + host + b"\r\n", 403),
            (b"GET / HTTP/1.1\r\n" + host * 2 + b"\r\n", 400),
            (b"POST / HTTP/1.1\r\n" + host + b"Content-Length: 1\r\nContent-Length: 1\r\n\r\n", 400),
            (b"GET /" + b"a" * 8192 + b" HTTP/1.1\r\n" + host + b"\r\n", 414),
            (b"GET / HTTP/1.1\r\n" + host + b"X-Test: " + b"a" * 16384 + b"\r\n\r\n", 431),
            (b"POST / HTTP/1.1\r\n" + host + b"Content-Length: 1048577\r\n\r\n", 413),
        )
        for request, status in cases:
            with self.subTest(status=status, request=request[:60]):
                self.reject(self.v4 + request, status)


if __name__ == "__main__":
    unittest.main(argv=sys.argv[:1])
