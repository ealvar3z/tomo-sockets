# tomo-sockets

Networking primitives for Tomo with a typed API for TCP, UDP, `select`, and TLS.

## What You Get
- TCP and UDP sockets: connect, bind, listen, accept, send, receive, close.
- TLS client wrapper on top of TCP (`TlsSocket`).
- Line buffers for both plain and TLS sockets (`SocketBuffer`, `TlsBuffer`).
- Per-call timeouts in milliseconds.
- Explicit result enums (`Success`, `Timeout`, `Closed`, `Failure(reason)`).

## Requirements
- Tomo compiler installed and working.
- OpenSSL dev/runtime libraries available for TLS (`libssl`, `libcrypto`).
- POSIX platform for full support (Linux/macOS). Windows is currently stubbed.

## Install
Use directly from this repo:

```sh
git clone https://github.com/ealvar3z/tomo-sockets
cd tomo-sockets
tomo -IL . your_program.tm
```

In your Tomo file, import either:
- `use sockets` (if installed as a Tomo library), or
- `use ./sockets.tm` (from this repo path).

Use via `modules.ini` (recommended):

```ini
[sockets]
version=v1.0
git=https://github.com/ealvar3z/tomo-sockets
```

Then in your program:

```tomo
use sockets
```

When `modules.ini` is present next to your source file, Tomo can resolve/install the module from git automatically.

## Quick Start (TCP)
```tomo
use ./sockets.tm

func main()
    server := TcpSocket.new()
    socket_or_fail(server.bind(SocketAddr("127.0.0.1", 0, SocketFamily.Inet)))
    socket_or_fail(server.listen())
    addr := socket_addr_or_fail(server.getsockname())

    client := TcpSocket.new()
    socket_or_fail(client.connect(SocketAddr("127.0.0.1", addr.port, SocketFamily.Inet), timeout_ms=2000))
    socket_or_fail(client.send("hello".utf8(), timeout_ms=2000))
    socket_or_fail(client.close())

    conn := socket_accept_or_fail(server.accept(timeout_ms=2000))
    data := socket_recv_or_fail(conn.receive(timeout_ms=2000))
    say(Text.from_utf8(data) or "")

    socket_or_fail(conn.close())
    socket_or_fail(server.close())
```

## Quick Start (TLS Client)
```tomo
use ./sockets.tm

func main()
    client := TcpSocket.new()
    socket_or_fail(
        client.connect(SocketAddr("irc.libera.chat", 6697, SocketFamily.Inet), timeout_ms=5000)
    )

    tls := tls_socket_or_fail(
        TlsSocket.wrap_client(client, config=TlsConfig(server_name="irc.libera.chat"))
    )
    tls_or_fail(tls.handshake(timeout_ms=5000))

    tls_or_fail(tls.send("PING :hello\r\n".utf8(), timeout_ms=2000))
    recv := tls.receive(timeout_ms=2000)
    say("$recv")

    tls_or_fail(tls.close())
```

## Examples
Run from repo root:

```sh
tomo examples/sockets_tcp_echo.tm
tomo examples/sockets_udp_sendrecv.tm
tomo examples/irc_client.tm -- --nick <nick> --channel "#tomo"
tomo examples/irc_client.tm -- --nick <nick> --channel "#tomo" --tls --port 6697
```

Notes:
- Program args are passed after `--` in Tomo.
- IRC client supports both plain TCP (`6667`) and TLS (`--tls --port 6697`).

## Testing
```sh
tomo test/sockets_test.tm
tomo test/buffer_test.tm
tomo test/select_test.tm
tomo test/tls_test.tm
```

## Error Handling Model
- Socket methods return enums like `SocketResult`, `SocketRecv`, `SocketAccept`.
- TLS methods return `TlsResult` / `TlsSocketResult`.
- Use `socket_or_fail(...)`, `socket_recv_or_fail(...)`, `tls_or_fail(...)`, and `tls_socket_or_fail(...)` for fail-fast flows.
- Use pattern matching (`when ... is ...`) when you need explicit timeout/retry behavior.

## Status
- POSIX implementation is active and tested.
- Windows implementation exists as unsupported stubs for now.
