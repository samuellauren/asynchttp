#!/usr/bin/env python3

import argparse
import http.server
import json
from pathlib import Path
import re
import socketserver
import ssl
import subprocess
import sys
import threading
import time


def create_root_certificate(stem):
    cert_path = stem + ".pem"
    key_path = stem + ".key"
    cmd = (
        "openssl",
        "req",
        "-newkey",
        "rsa",
        "-nodes",
        "-keyout",
        key_path,
        "-x509",
        "-subj",
        "/CN=Test root CA",
        "-days",
        "1",
        "-out",
        cert_path,
    )
    status = subprocess.run(cmd)
    assert status.returncode == 0
    return cert_path, key_path


def create_csr(stem):
    csr_path = stem + ".csr"
    key_path = stem + ".key"
    cmd = (
        "openssl",
        "req",
        "-newkey",
        "rsa",
        "-nodes",
        "-keyout",
        key_path,
        "-subj",
        "/CN=Test certificate",
        "-out",
        csr_path,
    )
    status = subprocess.run(cmd)
    assert status.returncode == 0
    return csr_path, key_path


def create_certificate(stem, CA):
    cert_path = stem + ".pem"
    config_path = stem + ".cnf"
    with open(config_path, "w") as f:
        f.write("subjectAltName = IP:127.0.0.1")
    csr_path, key_path = create_csr(stem)
    cmd = (
        "openssl",
        "x509",
        "-req",
        "-in",
        csr_path,
        "-CA",
        CA[0],
        "-CAkey",
        CA[1],
        "-CAcreateserial",
        "-extfile",
        config_path,
        "-days",
        "1",
        "-out",
        cert_path,
    )
    status = subprocess.run(cmd)
    assert status.returncode == 0
    return cert_path, key_path


def run(arch, args, env=None):
    if arch == "linux64":
        cmd = [
            "valgrind",
            "-q",
            "--leak-check=full",
            "--error-exitcode=123",
        ]
    else:
        cmd = []
    cmd += args
    return subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
    )


def tls_context(cert_files):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_files[0], keyfile=cert_files[1])
    return context


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        obj = {"key": "value"}
        content = json.dumps(obj).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.send_header("Content-Length", len(content))
        self.end_headers()
        try:
            self.wfile.write(content)
        except BrokenPipeError:
            pass


def test_https_linux(arch, stage_path):
    webclient_path = stage_path / "build" / "test" / "webclient"
    root_cert_files = create_root_certificate(str(stage_path / "root"))
    cert_files = create_certificate(str(stage_path / "test"), root_cert_files)
    httpd = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    httpd.socket = tls_context(cert_files).wrap_socket(
        httpd.socket, server_side=True
    )
    port = httpd.socket.getsockname()[1]
    url = "https://127.0.0.1:{}".format(port)
    thread = threading.Thread(target=httpd.serve_forever)
    thread.start()
    try:
        status = run(
            arch,
            [
                webclient_path,
                url,
            ],
            env={
                "SSL_CERT_FILE": root_cert_files[0],
            }
        )
        assert status.returncode == 0
        assert json.loads(status.stdout.decode()) == {"key": "value"}

        status = run(
            arch,
            [
                webclient_path,
                url,
                root_cert_files[0],
            ],
            env={},
        )
        assert status.returncode == 0
        assert json.loads(status.stdout.decode()) == {"key": "value"}
    finally:
        httpd.shutdown()
        thread.join()


def test_https_darwin(arch, stage_path):
    webclient_path = stage_path / "build" / "test" / "webclient"
    status = run(
        arch,
        [
            webclient_path,
            "https://github.com/",
        ],
    )
    assert status.returncode == 0


def test_jsonop(arch, stage_path):
    webclient_path = stage_path / "build" / "test" / "webclient"
    httpd = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = httpd.socket.getsockname()[1]
    url = "http://127.0.0.1:{}".format(port)
    thread = threading.Thread(target=httpd.serve_forever)
    thread.start()
    try:
        status = run(
            arch,
            [
                webclient_path,
                "--json",
                "--timeout",
                "1",
                url,
            ],
            env={},
        )
        assert status.returncode == 1

        status = run(
            arch,
            [
                webclient_path,
                "--json",
                url,
            ],
            env={},
        )
        assert status.returncode == 0
        assert json.loads(status.stdout.decode()) == {"key": "value"}
    finally:
        httpd.shutdown()
        thread.join()


BODY = json.dumps({"key": "value"}).encode("utf-8")
POOL_TRACE_EVENTS = "ASYNCHTTP-OP-REUSE|ASYNCHTTP-POOL-PROBE.*"


class KeepAliveHandler(http.server.BaseHTTPRequestHandler):
    """An HTTP/1.1 server whose connections the client is allowed to pool.

    The stock BaseHTTPRequestHandler speaks HTTP/1.0, which asynchttp
    never pools, so the tests above never exercise the idle connection
    pool."""

    protocol_version = "HTTP/1.1"
    # An abandoned keep-alive connection must not keep a handler thread
    # around forever.
    timeout = 5
    delay_after_response = 0
    after_response = b""
    close_after_response = False

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.send_header("Content-Length", len(BODY))
        self.end_headers()
        try:
            self.wfile.write(BODY)
            if self.delay_after_response:
                # Give the client time to consume the response and put
                # the connection into its pool before anything else
                # happens on the connection.
                time.sleep(self.delay_after_response)
            if self.after_response:
                self.wfile.write(self.after_response)
        except BrokenPipeError:
            pass
        if self.close_after_response:
            self.close_connection = True


class CloseAfterResponseHandler(KeepAliveHandler):
    """Closes the connection shortly after the response without
    announcing it with a Connection: close header. This is what the
    server did in the doormand core dump this test was written for."""

    delay_after_response = 0.5
    close_after_response = True


class UnsolicitedResponseHandler(KeepAliveHandler):
    """Sends a second, unsolicited response on the idle connection."""

    delay_after_response = 0.5
    after_response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"


class ThreadingServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


def serve(handler, cert_files=None):
    httpd = ThreadingServer(("127.0.0.1", 0), handler)
    scheme = "http"
    if cert_files:
        httpd.socket = tls_context(cert_files).wrap_socket(
            httpd.socket, server_side=True
        )
        scheme = "https"
    port = httpd.socket.getsockname()[1]
    thread = threading.Thread(target=httpd.serve_forever)
    thread.start()
    return httpd, thread, "{}://127.0.0.1:{}".format(scheme, port)


def get_twice(arch, stage_path, url, env):
    """Make two GET requests one second apart with a single http_client
    so that the connection sits in the idle pool in between. Return the
    pool related trace events that were emitted."""
    webclient_path = stage_path / "build" / "test" / "webclient"
    status = run(
        arch,
        [
            webclient_path,
            "--spam",
            "1",
            "--count",
            "2",
            "--trace-include",
            POOL_TRACE_EVENTS,
            url,
        ],
        env=env,
    )
    stderr = status.stderr.decode()
    assert status.returncode == 0, stderr
    assert status.stdout == BODY * 2, status.stdout
    return re.findall(r"\bASYNCHTTP-[A-Z-]+\b", stderr)


def test_pooled_connection_reused(arch, stage_path):
    httpd, thread, url = serve(KeepAliveHandler)
    try:
        events = get_twice(arch, stage_path, url, env={})
        assert "ASYNCHTTP-OP-REUSE" in events, events
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


def test_pooled_connection_closed_by_server(
    arch, stage_path, root_cert_files=None, cert_files=None
):
    httpd, thread, url = serve(CloseAfterResponseHandler, cert_files)
    try:
        env = {} if root_cert_files is None else {
            "SSL_CERT_FILE": root_cert_files[0]
        }
        events = get_twice(arch, stage_path, url, env)
        assert "ASYNCHTTP-POOL-PROBE-DISCONNECTED" in events, events
        assert "ASYNCHTTP-OP-REUSE" not in events, events
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


def test_pooled_connection_unsolicited_response(arch, stage_path):
    httpd, thread, url = serve(UnsolicitedResponseHandler)
    try:
        events = get_twice(arch, stage_path, url, env={})
        assert "ASYNCHTTP-POOL-PROBE-UNSOLICITED" in events, events
        assert "ASYNCHTTP-OP-REUSE" not in events, events
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("arch")
    args = parser.parse_args()
    stage_path = (
        Path(sys.argv[0]).resolve().parent.parent
        / "stage"
        / args.arch
    )
    if args.arch == "darwin":
        test_https_darwin(args.arch, stage_path)
    else:
        test_https_linux(args.arch, stage_path)
        root_cert_files = create_root_certificate(
            str(stage_path / "pool-root")
        )
        cert_files = create_certificate(
            str(stage_path / "pool-test"), root_cert_files
        )
        test_pooled_connection_closed_by_server(
            args.arch, stage_path, root_cert_files, cert_files
        )
    test_jsonop(args.arch, stage_path)
    test_pooled_connection_reused(args.arch, stage_path)
    test_pooled_connection_closed_by_server(args.arch, stage_path)
    test_pooled_connection_unsolicited_response(args.arch, stage_path)


if __name__ == "__main__":
    main()
