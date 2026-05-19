import asyncio
import struct
import socket
from proxy_vault.core.proxy_manager import ProxyManager


SOCKS5_VERSION = 5
NO_AUTH = 0
NO_ACCEPTABLE = 0xFF

CMD_CONNECT = 1
CMD_NOT_SUPPORTED = 7

ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4

REP_SUCCESS = 0
REP_GENERAL_FAILURE = 1
REP_CMD_NOT_SUPPORTED = 7
REP_ADDR_NOT_SUPPORTED = 8
REP_HOST_UNREACHABLE = 4


class SOCKS5Server:
    def __init__(self, manager: ProxyManager, host: str = "127.0.0.1", port: int = 1080):
        self._manager = manager
        self._host = host
        self._port = port
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, self._host, self._port,
        )

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await self._handle_handshake(reader, writer)
            await self._handle_request(reader, writer)
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        version, nmethods = struct.unpack("!BB", await reader.readexactly(2))
        if version != SOCKS5_VERSION:
            writer.write(struct.pack("!BB", SOCKS5_VERSION, NO_ACCEPTABLE))
            await writer.drain()
            return
        methods = await reader.readexactly(nmethods)
        if NO_AUTH in methods:
            writer.write(struct.pack("!BB", SOCKS5_VERSION, NO_AUTH))
        else:
            writer.write(struct.pack("!BB", SOCKS5_VERSION, NO_ACCEPTABLE))
        await writer.drain()

    async def _handle_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        version, cmd, rsv, atyp = struct.unpack("!BBBB", await reader.readexactly(4))
        if version != SOCKS5_VERSION or cmd != CMD_CONNECT:
            await self._send_reply(writer, REP_CMD_NOT_SUPPORTED)
            return

        if atyp == ATYP_IPV4:
            addr = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == ATYP_DOMAIN:
            domain_len = (await reader.readexactly(1))[0]
            addr = (await reader.readexactly(domain_len)).decode()
        elif atyp == ATYP_IPV6:
            addr = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        else:
            await self._send_reply(writer, REP_ADDR_NOT_SUPPORTED)
            return

        port = struct.unpack("!H", await reader.readexactly(2))[0]

        proxy = await self._manager.get_next_proxy()
        if proxy is None:
            await self._send_reply(writer, REP_GENERAL_FAILURE)
            return

        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(proxy.host, proxy.port),
                timeout=10,
            )
            # SOCKS5 handshake with upstream proxy
            remote_writer.write(struct.pack("!BBB", SOCKS5_VERSION, 1, NO_AUTH))
            await remote_writer.drain()
            resp = await asyncio.wait_for(remote_reader.readexactly(2), timeout=5)
            if resp[1] != NO_AUTH:
                await self._send_reply(writer, REP_GENERAL_FAILURE)
                remote_writer.close()
                return

            # Request upstream to connect to target
            req = struct.pack("!BBBB", SOCKS5_VERSION, CMD_CONNECT, 0, ATYP_DOMAIN)
            req += bytes([len(addr)]) + addr.encode() + struct.pack("!H", port)
            remote_writer.write(req)
            await remote_writer.drain()

            reply = await asyncio.wait_for(remote_reader.readexactly(4), timeout=10)
            if reply[1] != REP_SUCCESS:
                self._manager.mark_result(proxy.key, success=False)
                await self._send_reply(writer, reply[1])
                remote_writer.close()
                return

            # Read bound address from upstream reply
            batyp = reply[3]
            if batyp == ATYP_IPV4:
                await remote_reader.readexactly(4)
            elif batyp == ATYP_DOMAIN:
                blen = (await remote_reader.readexactly(1))[0]
                await remote_reader.readexactly(blen)
            elif batyp == ATYP_IPV6:
                await remote_reader.readexactly(16)
            await remote_reader.readexactly(2)  # port

            await self._send_reply(writer, REP_SUCCESS)
            self._manager.mark_result(proxy.key, success=True)

            await asyncio.gather(
                self._relay(reader, remote_writer),
                self._relay(remote_reader, writer),
            )
        except Exception:
            self._manager.mark_result(proxy.key, success=False)
            await self._send_reply(writer, REP_HOST_UNREACHABLE)

    async def _send_reply(self, writer: asyncio.StreamWriter, rep: int) -> None:
        writer.write(struct.pack("!BBBB", SOCKS5_VERSION, rep, 0, ATYP_IPV4) + b"\x00\x00\x00\x00" + struct.pack("!H", 0))
        try:
            await writer.drain()
        except Exception:
            pass

    async def _relay(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await asyncio.wait_for(reader.read(8192), timeout=300)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
