# tomo-sockets

Socket and networking primitives for Tomo, built by porting core LuaSocket
behavior into a small, explicit API.

## What this gives you
- TCP/UDP sockets with connect/bind/listen/accept/send/receive/close.
- Per-call timeouts (milliseconds).
- Address helpers (resolve/from_ip) and getsockname.
- Result enums for explicit error handling, plus `socket_*_or_fail` helpers.

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

Then import with `use sockets` (when installed) or `use ./tomo-sockets/sockets.tm`
for a direct path include.

## Examples

```sh
tomo examples/sockets_tcp_echo.tm
tomo examples/sockets_udp_sendrecv.tm
```

## Testing

```sh
tomo test/sockets_test.tm

```
Note: the test uses `tomo-pthreads`.

## Error handling
Most APIs return result enums (e.g., `SocketResult`, `SocketRecv`). Use pattern
matching or `socket_*_or_fail` helpers when a failure should abort.

## Platform notes
- POSIX sockets are implemented; Windows stubs are present but not wired yet.
- Timeouts are implemented with `poll` on POSIX.

## C API (shim)
All functions return `int` status codes; `0` means success. System errors are
reported via `out_err` (errno or WSA error).

```c
int ts_sock_init(int *out_err);
void ts_sock_shutdown(void);

int ts_tcp_create(struct ts_sock *s, int family, int *out_err);
int ts_udp_create(struct ts_sock *s, int family, int *out_err);
int ts_sock_close(struct ts_sock *s, int *out_err);

int ts_sock_connect(struct ts_sock *s, const struct ts_addr *addr,
    int timeout_ms, int *out_err);
int ts_sock_bind(struct ts_sock *s, const struct ts_addr *addr, int *out_err);
int ts_sock_listen(struct ts_sock *s, int backlog, int *out_err);
int ts_sock_accept(struct ts_sock *s, struct ts_sock *out_client,
    struct ts_addr *out_peer, int timeout_ms, int *out_err);
int ts_sock_getsockname(struct ts_sock *s, struct ts_addr *out_addr, int *out_err);

int ts_sock_send(struct ts_sock *s, const void *buf, size_t len,
    int timeout_ms, size_t *out_sent, int *out_err);
int ts_sock_recv(struct ts_sock *s, void *buf, size_t len,
    int timeout_ms, size_t *out_got, int *out_err);
int ts_sock_sendto(struct ts_sock *s, const void *buf, size_t len,
    const struct ts_addr *addr, int timeout_ms, size_t *out_sent, int *out_err);
int ts_sock_recvfrom(struct ts_sock *s, void *buf, size_t len,
    struct ts_addr *out_addr, int timeout_ms, size_t *out_got, int *out_err);

int ts_sock_set_nonblocking(struct ts_sock *s, int enable, int *out_err);
int ts_sock_set_sockopt(struct ts_sock *s, enum ts_sockopt opt,
    int value, int *out_err);
int ts_sock_get_sockopt(struct ts_sock *s, enum ts_sockopt opt,
    int *out_value, int *out_err);

int ts_addr_resolve(const char *host, const char *service, int family,
    int socktype, struct ts_addr *out_addr, int *out_err);
int ts_addr_to_string(const struct ts_addr *addr, char *host, size_t host_len,
    char *service, size_t service_len, int *out_err);
const char *ts_addr_strerror(int err);
```

## Tomo API (core)

Types and results:
- `SocketFamily(Inet, Inet6)`
- `SocketType(Tcp, Udp)`
- `SocketResult(Success, Timeout, Closed, Failure(reason:Text))`
- `SocketAccept(Ok(sock:TcpSocket), Timeout, Closed, Failure(reason:Text))`
- `SocketRecv(Ok(data:[Byte]), Timeout, Closed, Failure(reason:Text))`
- `RecvFrom(addr:SocketAddr, data:[Byte])`
- `SocketRecvFrom(Ok(value:RecvFrom), Timeout, Closed, Failure(reason:Text))`
- `SocketValue(Ok(value:Int), Failure(reason:Text))`
- `SocketOption(ReuseAddr, ReusePort, TcpNoDelay, KeepAlive, Broadcast, Ipv6V6Only,
  RecvBufSize, SendBufSize)`
- `SocketAddr(host:Text, port:Int, family:SocketFamily)`
- `SocketAddrResult(Ok(addr:SocketAddr), Failure(reason:Text))`

Operations:
- `TcpSocket.new(family=SocketFamily.Inet -> TcpSocket)`
- `TcpSocket.connect(addr:SocketAddr, timeout_ms:Int=0 -> SocketResult)`
- `TcpSocket.bind(addr:SocketAddr -> SocketResult)`
- `TcpSocket.listen(backlog=32 -> SocketResult)`
- `TcpSocket.accept(timeout_ms:Int=0 -> SocketAccept)`
- `TcpSocket.getsockname(->SocketAddrResult)`
- `TcpSocket.send(data:[Byte], timeout_ms:Int=0 -> SocketResult)`
- `TcpSocket.receive(max_bytes:Int=8192, timeout_ms:Int=0 -> SocketRecv)`
- `TcpSocket.close(->SocketResult)`
- `TcpSocket.set_option(option:SocketOption, value:Int -> SocketResult)`
- `TcpSocket.get_option(option:SocketOption -> SocketValue)`

- `UdpSocket.new(family=SocketFamily.Inet -> UdpSocket)`
- `UdpSocket.bind(addr:SocketAddr -> SocketResult)`
- `UdpSocket.connect(addr:SocketAddr, timeout_ms:Int=0 -> SocketResult)`
- `UdpSocket.send(data:[Byte], timeout_ms:Int=0 -> SocketResult)`
- `UdpSocket.send_to(addr:SocketAddr, data:[Byte], timeout_ms:Int=0 -> SocketResult)`
- `UdpSocket.getsockname(->SocketAddrResult)`
- `UdpSocket.receive(max_bytes:Int=8192, timeout_ms:Int=0 -> SocketRecv)`
- `UdpSocket.receive_from(max_bytes:Int=8192, timeout_ms:Int=0 -> SocketRecvFrom)`
- `UdpSocket.close(->SocketResult)`
- `UdpSocket.set_option(option:SocketOption, value:Int -> SocketResult)`
- `UdpSocket.get_option(option:SocketOption -> SocketValue)`

Address helpers:
- `SocketAddr.resolve(host:Text, port:Int, family:SocketFamily=SocketFamily.Inet -> SocketAddrResult)`
- `SocketAddr.from_ip(ip:Text, port:Int, family:SocketFamily=SocketFamily.Inet -> SocketAddrResult)`

