import base64
import json
import os
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse


class WebSocketError(RuntimeError):
    pass


class WebSocket:
    def __init__(self, url, timeout=30):
        parsed = urlparse(url)
        self._sock = socket.create_connection((parsed.hostname, parsed.port), timeout=timeout)
        self._sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET {parsed.path or '/'} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{parsed.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self._sock.sendall(request.encode())
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise WebSocketError("connection closed during handshake")
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        status_line = head.split(b"\r\n")[0]
        if b"101" not in status_line:
            raise WebSocketError(f"websocket handshake failed: {status_line!r}")
        self._buffer = rest

    def _read(self, count):
        while len(self._buffer) < count:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise WebSocketError("connection closed")
            self._buffer += chunk
        out, self._buffer = self._buffer[:count], self._buffer[count:]
        return out

    def send(self, payload):
        data = json.dumps(payload).encode()
        header = bytearray([0x81])
        mask = os.urandom(4)
        length = len(data)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", length)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", length)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self._sock.sendall(bytes(header) + masked)

    def _recv_frame(self):
        b1, b2 = self._read(2)
        fin = b1 & 0x80
        opcode = b1 & 0x0F
        masked = b2 & 0x80
        length = b2 & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._read(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._read(8))[0]
        if masked:
            mask = self._read(4)
            data = bytes(c ^ mask[i % 4] for i, c in enumerate(self._read(length)))
        else:
            data = self._read(length)
        if opcode == 0x9:
            self._sock.sendall(b"\x8a\x80" + os.urandom(4))
            return None, False
        if opcode == 0xA:
            return None, False
        if opcode == 0x8:
            raise WebSocketError("connection closed by peer")
        return data, bool(fin)

    def recv(self):
        payload = b""
        while True:
            data, fin = self._recv_frame()
            if data is None:
                continue
            payload += data
            if fin:
                return json.loads(payload.decode())

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass


class DevTools:
    def __init__(self, ws_url, timeout=30):
        self._ws = WebSocket(ws_url, timeout=timeout)
        self._next_id = 0
        self._timeout = timeout

    def call(self, method, params=None):
        self._next_id += 1
        message_id = self._next_id
        payload = {"id": message_id, "method": method}
        if params:
            payload["params"] = params
        self._ws.send(payload)
        deadline = time.time() + self._timeout
        while time.time() < deadline:
            message = self._ws.recv()
            if message.get("id") == message_id:
                if "error" in message:
                    raise WebSocketError(f"{method} failed: {message['error']}")
                return message.get("result", {})
        raise WebSocketError(f"{method} timed out")

    def cookies(self):
        return self.call("Storage.getCookies").get("cookies", [])

    def close(self):
        self._ws.close()


def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class Chrome:
    def __init__(self, binary, profile_dir, headless=False):
        self.binary = binary
        self.profile_dir = str(profile_dir)
        self.headless = headless
        self.port = None
        self.process = None
        self.devtools = None

    def _endpoint(self):
        return f"http://127.0.0.1:{self.port}"

    def _wait_for_debugger(self, timeout=30):
        deadline = time.time() + timeout
        last_error = None
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(
                    f"{self._endpoint()}/json/version", timeout=2
                ) as response:
                    return json.load(response)
            except (urllib.error.URLError, OSError, ValueError) as error:
                last_error = error
                if self.process and self.process.poll() is not None:
                    raise WebSocketError(
                        "chrome exited before the debug port was available"
                    )
                time.sleep(0.2)
        raise WebSocketError(f"chrome debug port not reachable: {last_error}")

    def open(self, url, timeout=30):
        self.port = free_port()
        os.makedirs(self.profile_dir, exist_ok=True)
        args = [
            self.binary,
            f"--remote-debugging-port={self.port}",
            f"--user-data-dir={self.profile_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            "--no-service-autorun",
            "--password-store=basic",
        ]
        if self.headless:
            args.append("--headless=new")
        args.append(url)
        self.process = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        version = self._wait_for_debugger(timeout=timeout)
        self.devtools = DevTools(version["webSocketDebuggerUrl"])
        return self.devtools

    def close(self):
        if self.devtools:
            try:
                self.devtools.close()
            except Exception:
                pass
            self.devtools = None
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=10)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
        self.process = None
