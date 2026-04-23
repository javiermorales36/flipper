from __future__ import annotations

import argparse
import binascii
import enum
import math
import os
from pathlib import Path
import time

import serial
import serial.tools.list_ports as list_ports


class StorageErrorCode(enum.Enum):
    OK = "OK"
    NOT_READY = "filesystem not ready"
    EXIST = "file/dir already exist"
    NOT_EXIST = "file/dir not exist"
    INVALID_PARAMETER = "invalid parameter"
    DENIED = "access denied"
    INVALID_NAME = "invalid name/path"
    INTERNAL = "internal error"
    NOT_IMPLEMENTED = "function not implemented"
    ALREADY_OPEN = "file is already open"
    UNKNOWN = "unknown error"

    @classmethod
    def from_value(cls, value: str | bytes) -> "StorageErrorCode":
        if isinstance(value, bytes):
            value = value.decode("ascii")
        for code in cls:
            if code.value == value:
                return code
        return cls.UNKNOWN


class FlipperUsbStorageError(RuntimeError):
    @staticmethod
    def from_error_code(path: str, error_code: StorageErrorCode) -> "FlipperUsbStorageError":
        return FlipperUsbStorageError(f"Storage error: path '{path}': {error_code.value}")


def resolve_flipper_port(portname: str = "auto") -> str:
    if portname != "auto":
        return portname

    flippers = list(list_ports.grep("flip_"))
    if len(flippers) == 1:
        return flippers[0].device
    if len(flippers) == 0:
        raise FlipperUsbStorageError("Failed to find connected Flipper")
    raise FlipperUsbStorageError("More than one Flipper is attached")


def probe_flipper_port(portname: str = "auto") -> str:
    resolved_port = resolve_flipper_port(portname)
    with FlipperUsbStorage(resolved_port) as storage:
        storage.exist_dir("/ext")
    return resolved_port


class BufferedRead:
    def __init__(self, stream: serial.Serial):
        self.buffer = bytearray()
        self.stream = stream

    def until(self, eol: str = "\n", cut_eol: bool = True) -> bytes:
        needle = eol.encode("ascii")
        while True:
            index = self.buffer.find(needle)
            if index >= 0:
                if cut_eol:
                    payload = self.buffer[:index]
                else:
                    payload = self.buffer[: index + len(needle)]
                self.buffer = self.buffer[index + len(needle) :]
                return bytes(payload)

            read_size = max(1, self.stream.in_waiting)
            data = self.stream.read(read_size)
            self.buffer.extend(data)


class FlipperUsbStorage:
    CLI_PROMPT = ">: "
    CLI_EOL = "\r\n"

    def __init__(self, portname: str, chunk_size: int = 8192, timeout: float = 2.0, show_progress: bool = False):
        self.port = serial.Serial()
        self.port.port = portname
        self.port.timeout = timeout
        self.port.baudrate = 115200
        self.read = BufferedRead(self.port)
        self.chunk_size = chunk_size
        self.show_progress = show_progress

    def __enter__(self) -> "FlipperUsbStorage":
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.stop()

    def start(self) -> None:
        self.port.open()
        time.sleep(0.5)
        self.read.until(self.CLI_PROMPT)
        self.port.reset_input_buffer()
        self.send("device_info\r")
        self.read.until("hardware_model")
        self.read.until(self.CLI_PROMPT)

    def stop(self) -> None:
        self.port.close()

    def send(self, line: str) -> None:
        self.port.write(line.encode("ascii"))

    def send_and_wait_eol(self, line: str) -> bytes:
        self.send(line)
        return self.read.until(self.CLI_EOL)

    def has_error(self, data: bytes | str) -> bool:
        if isinstance(data, str):
            data = data.encode("ascii", errors="ignore")
        return b"Storage error:" in data

    def get_error(self, data: bytes) -> StorageErrorCode:
        _, error_text = data.decode("ascii").split(": ", 1)
        return StorageErrorCode.from_value(error_text.strip())

    def _check_no_error(self, response: bytes, path: str) -> None:
        if self.has_error(response):
            raise FlipperUsbStorageError.from_error_code(path, self.get_error(response))

    def _list_entries(self, path: str) -> list[tuple[str, str, str]]:
        normalized_path = path.replace("//", "/")
        self.send_and_wait_eol(f'storage list "{normalized_path}"\r')
        data = self.read.until(self.CLI_PROMPT)
        lines = data.split(b"\r\n")
        entries: list[tuple[str, str, str]] = []
        for raw_line in lines:
            try:
                line = raw_line.decode("ascii").strip()
            except Exception:
                continue

            if not line or line == "Empty":
                continue
            if self.has_error(line):
                raise FlipperUsbStorageError.from_error_code(normalized_path, self.get_error(line.encode("ascii")))

            entry_type, payload = line.split(" ", 1)
            if entry_type == "[D]":
                entries.append(("dir", payload, ""))
                continue
            if entry_type == "[F]":
                name, size = payload.rsplit(" ", 1)
                entries.append(("file", name, size))
        return entries

    def list_tree(self, path: str = "/") -> list[str]:
        normalized_path = path.replace("//", "/")
        output: list[str] = []
        for entry_type, name, size in self._list_entries(normalized_path):
            full_path = (normalized_path + "/" + name).replace("//", "/")
            if entry_type == "dir":
                output.append(full_path)
                output.extend(self.list_tree(full_path))
            else:
                output.append(f"{full_path}, size {size}")
        return output

    def exist(self, path: str) -> bool:
        self.send_and_wait_eol(f'storage stat "{path}"\r')
        response = self.read.until(self.CLI_EOL)
        self.read.until(self.CLI_PROMPT)
        return not self.has_error(response)

    def exist_dir(self, path: str) -> bool:
        self.send_and_wait_eol(f'storage stat "{path}"\r')
        response = self.read.until(self.CLI_EOL)
        self.read.until(self.CLI_PROMPT)
        if self.has_error(response):
            error_code = self.get_error(response)
            if error_code in (StorageErrorCode.NOT_EXIST, StorageErrorCode.INVALID_NAME):
                return False
            raise FlipperUsbStorageError.from_error_code(path, error_code)
        return response == b"Directory" or response.startswith(b"Storage")

    def exist_file(self, path: str) -> bool:
        self.send_and_wait_eol(f'storage stat "{path}"\r')
        response = self.read.until(self.CLI_EOL)
        self.read.until(self.CLI_PROMPT)
        return b"File, size:" in response

    def mkdir(self, path: str) -> None:
        self.send_and_wait_eol(f'storage mkdir "{path}"\r')
        response = self.read.until(self.CLI_EOL)
        self.read.until(self.CLI_PROMPT)
        self._check_no_error(response, path)

    def remove(self, path: str) -> None:
        self.send_and_wait_eol(f'storage remove "{path}"\r')
        response = self.read.until(self.CLI_EOL)
        self.read.until(self.CLI_PROMPT)
        self._check_no_error(response, path)

    def send_file(self, local_path: str, flipper_path: str) -> None:
        if self.exist_file(flipper_path):
            self.remove(flipper_path)

        with open(local_path, "rb") as stream:
            file_size = os.fstat(stream.fileno()).st_size
            start_time = time.time()
            while True:
                chunk = stream.read(self.chunk_size)
                chunk_size = len(chunk)
                if chunk_size == 0:
                    break

                self.send_and_wait_eol(f'storage write_chunk "{flipper_path}" {chunk_size}\r')
                answer = self.read.until(self.CLI_EOL)
                if self.has_error(answer):
                    last_error = self.get_error(answer)
                    self.read.until(self.CLI_PROMPT)
                    raise FlipperUsbStorageError.from_error_code(flipper_path, last_error)

                self.port.write(chunk)
                self.read.until(self.CLI_PROMPT)

                if self.show_progress and file_size > 0:
                    sent = stream.tell()
                    percent = math.ceil(sent / file_size * 100)
                    total_chunks = math.ceil(file_size / self.chunk_size)
                    current_chunk = math.ceil(sent / self.chunk_size)
                    speed = sent / (time.time() - start_time + 0.0001)
                    print(
                        f"\r<{percent:3d}%, chunk {current_chunk:2d} of {total_chunks:2d} @ {speed / 1024:.2f} kb/s",
                        end="",
                    )
        if self.show_progress:
            print()

    def read_file(self, flipper_path: str) -> bytes:
        file_data = bytearray()
        self.send_and_wait_eol(f'storage read_chunks "{flipper_path}" {self.chunk_size}\r')
        answer = self.read.until(self.CLI_EOL)
        if self.has_error(answer):
            last_error = self.get_error(answer)
            self.read.until(self.CLI_PROMPT)
            raise FlipperUsbStorageError.from_error_code(flipper_path, last_error)

        file_size = int(answer.split(b": ")[1])
        bytes_read = 0
        start_time = time.time()

        while bytes_read < file_size:
            self.read.until("Ready?" + self.CLI_EOL)
            self.send("y")
            chunk_size = min(file_size - bytes_read, self.chunk_size)
            file_data.extend(self.port.read(chunk_size))
            bytes_read += chunk_size

            if self.show_progress and file_size > 0:
                percent = math.ceil(bytes_read / file_size * 100)
                total_chunks = math.ceil(file_size / self.chunk_size)
                current_chunk = math.ceil(bytes_read / self.chunk_size)
                speed = bytes_read / (time.time() - start_time + 0.0001)
                print(
                    f"\r>{percent:3d}%, chunk {current_chunk:2d} of {total_chunks:2d} @ {speed / 1024:.2f} kb/s",
                    end="",
                )

        if self.show_progress:
            print()
        self.read.until(self.CLI_PROMPT)
        return bytes(file_data)

    def receive_file(self, flipper_path: str, local_path: str) -> None:
        local = Path(local_path)
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(self.read_file(flipper_path))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Standalone Flipper USB storage client")
    parser.add_argument("-p", "--port", default="auto", help="Flipper CDC port. Defaults to auto.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    parser_list = subparsers.add_parser("list", help="Recursively list files and directories")
    parser_list.add_argument("flipper_path")

    parser_mkdir = subparsers.add_parser("mkdir", help="Create a directory")
    parser_mkdir.add_argument("flipper_path")

    parser_remove = subparsers.add_parser("remove", help="Remove a file or directory")
    parser_remove.add_argument("flipper_path")

    parser_read = subparsers.add_parser("read", help="Read a file and print it")
    parser_read.add_argument("flipper_path")

    parser_receive = subparsers.add_parser("receive", help="Receive a file from the Flipper")
    parser_receive.add_argument("flipper_path")
    parser_receive.add_argument("local_path")

    parser_send = subparsers.add_parser("send", help="Send a file to the Flipper")
    parser_send.add_argument("local_path")
    parser_send.add_argument("flipper_path")

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        resolved_port = resolve_flipper_port(args.port)
        print(f"Using Flipper on {resolved_port}")
        with FlipperUsbStorage(resolved_port, show_progress=True) as storage:
            if args.command == "list":
                for line in storage.list_tree(args.flipper_path):
                    print(line)
            elif args.command == "mkdir":
                storage.mkdir(args.flipper_path)
            elif args.command == "remove":
                storage.remove(args.flipper_path)
            elif args.command == "read":
                data = storage.read_file(args.flipper_path)
                try:
                    print("Text data:")
                    print(data.decode())
                except Exception:
                    print("Binary hexadecimal data:")
                    print(binascii.hexlify(data).decode())
            elif args.command == "receive":
                storage.receive_file(args.flipper_path, args.local_path)
            elif args.command == "send":
                storage.send_file(args.local_path, args.flipper_path)
            else:
                raise FlipperUsbStorageError(f"Unsupported command: {args.command}")
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())