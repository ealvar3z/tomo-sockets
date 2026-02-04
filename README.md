# tomo-sockets

Socket and networking primitives for Tomo, modeled on LuaSocket core behavior.

Tomo is a small compiled language with Python-like syntax and explicit types.
If you know LuaSocket, think of this as `socket.core` for Tomo, with a typed
API and result enums instead of exceptions.

## What you get
- TCP and UDP sockets: connect, bind, listen, accept, send, receive, close.
- Per-call timeouts (milliseconds).
- Address helpers: resolve/from_ip and getsockname.
- Result enums + `socket_*_or_fail` helpers for explicit errors.

## Quick start
```tomo
use sockets

func main()
    server := TcpSocket.new()
    socket_or_fail(server.bind(SocketAddr("127.0.0.1", 0, SocketFamily.Inet)))
    socket_or_fail(server.listen())
    addr := socket_addr_or_fail(server.getsockname())

    client := TcpSocket.new()
    socket_or_fail(client.connect(SocketAddr("127.0.0.1", addr.port, SocketFamily.Inet), timeout_ms=2000))
    socket_or_fail(client.send("hello".utf8()))
    socket_or_fail(client.close())

    conn := socket_accept_or_fail(server.accept(timeout_ms=2000))
    data := socket_recv_or_fail(conn.receive(timeout_ms=2000))
    say(Text.from_utf8(data) or "")
    socket_or_fail(conn.close())
    socket_or_fail(server.close())
```

## Install / use standalone
```sh
git clone https://github.com/ealvar3z/tomo-sockets
tomo -IL ./tomo-sockets your_program.tm
```
Import with `use sockets` (when installed) or `use ./tomo-sockets/sockets.tm`.

## Examples
```sh
tomo examples/sockets_tcp_echo.tm
tomo examples/sockets_udp_sendrecv.tm
```

## Testing
```sh
tomo test/sockets_test.tm
```
Note: tests use `tomo-pthreads`.

## Error handling
Most APIs return result enums (`SocketResult`, `SocketRecv`, etc.). Use pattern
matching or the `socket_*_or_fail` helpers when a failure should abort.

## Platform notes
- POSIX sockets are implemented; Windows stubs exist but are not wired yet.
- Timeouts use `poll` on POSIX.
