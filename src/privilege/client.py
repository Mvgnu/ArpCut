"""Unprivileged client to the root helper daemon.

The GUI uses this to drive privileged operations without holding any privilege
itself. ``connect`` can be injected (tests wire an in-memory socket); otherwise it
dials the helper's Unix socket.
"""
from __future__ import annotations

import json
import queue
import socket
import threading
from typing import Callable, Optional

from privilege.protocol import Request, Response, decode_response, encode
from privilege.service import SOCKET_PATH


class HelperError(Exception):
    """The helper is unreachable or returned a malformed reply."""


class HelperClient:
    """Talks to the root helper over its Unix socket (one request per call)."""

    def __init__(self, sock_path: str = SOCKET_PATH,
                 connect: Optional[Callable[[], socket.socket]] = None,
                 timeout: float = 5.0) -> None:
        self._sock_path = sock_path
        self._connect = connect
        self._timeout = timeout

    def _open(self) -> socket.socket:
        if self._connect is not None:
            return self._connect()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self._timeout)
        s.connect(self._sock_path)
        return s

    def call(self, cmd: str, **args) -> Response:
        conn = self._open()
        try:
            conn.sendall(encode(Request(cmd=cmd, args=args)))
            buf = b''
            while b'\n' not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            if not buf:
                raise HelperError('no response from helper')
            return decode_response(buf.split(b'\n', 1)[0])
        finally:
            conn.close()

    def available(self) -> bool:
        """True if the helper is installed and responding."""
        try:
            return self.call('ping').result == 'pong'
        except (OSError, HelperError, ValueError):
            return False


class HelperSession:
    """A *persistent* connection to the helper: request/response plus pushed
    events, held for the GUI's whole life.

    Holding it open is what lets the helper detect the GUI going away (quit or
    crash) and restore every device — so nothing is left blocked. Events (e.g.
    live traffic ``flows``) arrive on ``on_event`` without polling.
    """

    def __init__(self, sock_path: str = SOCKET_PATH,
                 connect: Optional[Callable[[], socket.socket]] = None,
                 on_event: Optional[Callable[[dict], None]] = None,
                 timeout: float = 5.0) -> None:
        self._sock_path = sock_path
        self._connect = connect
        self.on_event = on_event
        self._timeout = timeout
        self._lock = threading.Lock()        # one request in flight at a time
        self._resp: queue.Queue = queue.Queue()
        self._conn: Optional[socket.socket] = None
        self._alive = False

    def _open(self) -> socket.socket:
        if self._connect is not None:
            return self._connect()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self._timeout)
        s.connect(self._sock_path)
        return s

    def start(self) -> bool:
        """Connect and subscribe. Returns True if the session is live."""
        if self._alive:
            return True
        try:
            self._conn = self._open()
        except OSError:
            return False
        self._alive = True
        threading.Thread(target=self._read_loop, daemon=True).start()
        try:
            return self.call('subscribe').ok
        except (OSError, HelperError):
            self._alive = False
            return False

    def _read_loop(self) -> None:
        buf = b''
        try:
            while self._alive:
                chunk = self._conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b'\n' in buf:
                    line, buf = buf.split(b'\n', 1)
                    if not line.strip():
                        continue
                    try:
                        frame = json.loads(line.decode('utf-8'))
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if isinstance(frame, dict) and frame.get('event'):
                        if self.on_event:
                            try:
                                self.on_event(frame)
                            except Exception:  # noqa: BLE001
                                pass
                    else:
                        self._resp.put(frame)
        except OSError:
            pass
        finally:
            self._alive = False
            self._resp.put(None)  # wake any waiting call()

    def call(self, cmd: str, **args) -> Response:
        with self._lock:
            if not self._alive or self._conn is None:
                raise HelperError('helper session not connected')
            self._conn.sendall(encode(Request(cmd=cmd, args=args)))
            try:
                frame = self._resp.get(timeout=self._timeout)
            except queue.Empty:
                raise HelperError(f'{cmd} timed out')
            if frame is None:
                raise HelperError('helper session closed')
            return Response(ok=bool(frame.get('ok')), result=frame.get('result'),
                            error=frame.get('error'))

    def available(self) -> bool:
        return self._alive

    def close(self) -> None:
        self._alive = False
        try:
            if self._conn:
                self._conn.close()
        except OSError:
            pass
