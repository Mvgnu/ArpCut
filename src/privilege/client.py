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

from privilege.protocol import MAX_FRAME_BYTES, Request, Response, decode_response, encode
from privilege.service import SOCKET_PATH

# Scan/discovery and multi-rule teardown legitimately take longer than a health
# check. Each operation remains bounded; a real timeout still drops the session.
_OPERATION_TIMEOUTS = {
    'scan': 300.0,
    'probe': 30.0,
    'block_host': 60.0,
    'refresh_hosts': 120.0,
    'cleanup': 120.0,
    'set_iface': 120.0,
    'kill_all': 120.0,
    'unkill_all': 120.0,
}


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
        try:
            s.settimeout(self._timeout)
            s.connect(self._sock_path)
        except OSError:
            s.close()
            raise
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
                if len(buf) > MAX_FRAME_BYTES:
                    raise HelperError('helper response is too large')
            if b'\n' not in buf:
                raise HelperError('incomplete response from helper')
            try:
                return decode_response(buf.split(b'\n', 1)[0])
            except ValueError as exc:
                raise HelperError(f'invalid response from helper: {exc}') from exc
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
        self._start_lock = threading.Lock()
        self._resp: queue.Queue = queue.Queue()
        self._conn: Optional[socket.socket] = None
        self._alive = False

    def _open(self) -> socket.socket:
        if self._connect is not None:
            return self._connect()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.settimeout(self._timeout)
            s.connect(self._sock_path)
        except OSError:
            s.close()
            raise
        return s

    def start(self) -> bool:
        """Connect and subscribe. Returns True if the session is live."""
        with self._start_lock:
            if self._alive:
                return True
            self.close()
            try:
                conn = self._open()
                # The session is intentionally idle between GUI actions. Request
                # deadlines belong to call(), not the background socket reader.
                conn.settimeout(None)
            except OSError:
                return False
            self._conn = conn
            self._resp = responses = queue.Queue()
            self._alive = True
            threading.Thread(target=self._read_loop, args=(conn, responses),
                             daemon=True).start()
            try:
                if self.call('subscribe').ok:
                    return True
            except (OSError, HelperError):
                pass
            self._disconnect(conn, responses)
            return False

    def _read_loop(self, conn, responses) -> None:
        buf = b''
        try:
            while self._conn is conn and self._alive:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b'\n' in buf:
                    line, buf = buf.split(b'\n', 1)
                    if len(line) > MAX_FRAME_BYTES:
                        raise HelperError('helper response is too large')
                    if not line.strip():
                        continue
                    try:
                        frame = json.loads(line.decode('utf-8'))
                    except (ValueError, UnicodeDecodeError) as exc:
                        raise HelperError('invalid helper response') from exc
                    if isinstance(frame, dict) and frame.get('event'):
                        if self.on_event:
                            try:
                                self.on_event(frame)
                            except Exception:  # noqa: BLE001
                                pass
                    else:
                        responses.put(decode_response(line))
                if len(buf) > MAX_FRAME_BYTES:
                    raise HelperError('helper response is too large')
        except (OSError, ValueError, HelperError):
            pass
        finally:
            self._disconnect(conn, responses)

    def call(self, cmd: str, **args) -> Response:
        with self._lock:
            if not self._alive or self._conn is None:
                raise HelperError('helper session not connected')
            conn, responses = self._conn, self._resp
            try:
                conn.sendall(encode(Request(cmd=cmd, args=args)))
                frame = responses.get(timeout=max(self._timeout, _OPERATION_TIMEOUTS.get(cmd, 0)))
            except (OSError, queue.Empty) as exc:
                # This protocol has no request IDs. Once a call times out the
                # connection cannot safely match a late reply to later calls.
                self._disconnect(conn, responses)
                raise HelperError(f'{cmd} failed or timed out') from exc
            if frame is None:
                raise HelperError('helper session closed')
            return frame

    def available(self) -> bool:
        return self._alive

    def close(self) -> None:
        self._disconnect(self._conn, self._resp)

    def _disconnect(self, conn, responses) -> None:
        if self._conn is conn:
            self._alive = False
            self._conn = None
        # close() alone does not wake a thread blocked in recv() on every OS.
        # shutdown() makes the server observe EOF immediately, triggering cleanup.
        try:
            if conn:
                conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        if conn:
            conn.close()
        responses.put(None)
