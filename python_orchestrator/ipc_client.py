"""
High-Speed IPC Client connecting Python Orchestrator to C Agent.
Uses Windows Named Pipes (\\.\\pipe\\MalwareAnalyzerPipe) or local sockets.
Receives raw byte buffers and filesystem events from C Agent at wire speed.
"""

import os
import sys
import time
import ctypes
from typing import Callable, Optional

DEFAULT_PIPE_NAME = r"\\.\pipe\MalwareAnalyzerPipe"
AGENT_MAGIC = 0x4D414C57  # 'MALW'


class IPCMessagePacket(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("event_type", ctypes.c_uint32),
        ("file_path_len", ctypes.c_uint32),
        ("file_size", ctypes.c_uint64),
        ("preview_len", ctypes.c_uint32),
        ("is_pe", ctypes.c_uint32),
        ("is_elf", ctypes.c_uint32),
        ("file_path", ctypes.c_char * 512),
        ("header_preview", ctypes.c_uint8 * 4096),
    ]


class IPCClient:
    def __init__(self, pipe_name: str = DEFAULT_PIPE_NAME):
        self.pipe_name = pipe_name
        self.handle = None
        self.is_connected = False

    def connect(self, timeout_sec: float = 10.0) -> bool:
        """Connect to the C Agent's Named Pipe server."""
        if os.name != "nt":
            return False

        kernel32 = ctypes.windll.kernel32
        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        OPEN_EXISTING = 3
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

        start_time = time.time()
        while time.time() - start_time < timeout_sec:
            h_pipe = kernel32.CreateFileA(
                self.pipe_name.encode("ascii"),
                GENERIC_READ | GENERIC_WRITE,
                0,
                None,
                OPEN_EXISTING,
                0,
                None
            )

            if h_pipe != INVALID_HANDLE_VALUE and h_pipe != 0:
                self.handle = h_pipe
                self.is_connected = True
                return True

            # Wait a moment for the pipe
            time.sleep(0.5)

        return False

    def read_packet(self) -> Optional[dict]:
        """Read a single IPC packet from the pipe."""
        if not self.is_connected or not self.handle:
            return None

        kernel32 = ctypes.windll.kernel32
        packet = IPCMessagePacket()
        bytes_to_read = ctypes.sizeof(IPCMessagePacket)
        bytes_read = ctypes.c_ulong(0)

        success = kernel32.ReadFile(
            self.handle,
            ctypes.byref(packet),
            bytes_to_read,
            ctypes.byref(bytes_read),
            None
        )

        if not success or bytes_read.value != bytes_to_read:
            return None

        if packet.magic != AGENT_MAGIC:
            return None

        raw_path = packet.file_path.split(b"\x00")[0].decode("utf-8", errors="replace")
        preview_data = bytes(packet.header_preview[:packet.preview_len])

        return {
            "magic": packet.magic,
            "event_type": packet.event_type,
            "file_size": packet.file_size,
            "is_pe": bool(packet.is_pe),
            "is_elf": bool(packet.is_elf),
            "file_path": raw_path,
            "preview_len": packet.preview_len,
            "header_preview": preview_data
        }

    def listen_loop(self, on_event_callback: Callable[[dict], None], stop_event=None):
        """Continuous event listener loop."""
        while True:
            if stop_event and stop_event.is_set():
                break

            pkt = self.read_packet()
            if pkt:
                on_event_callback(pkt)
            else:
                time.sleep(0.1)

    def close(self):
        if self.handle:
            ctypes.windll.kernel32.CloseHandle(self.handle)
            self.handle = None
        self.is_connected = False

