use <errno.h>
use <gc.h>
use <stdlib.h>
use <string.h>

use ./sockets.h
use ./sockets.c
use ./sockets_posix.c
use ./sockets_addr.c
use ./sockets_win.c

enum SocketFamily(Inet, Inet6)

enum SocketType(Tcp, Udp)

enum SocketResult(Success, Timeout, Closed, Failure(reason:Text))
    func is_timeout(r:SocketResult -> Bool)
        when r is Timeout return yes
        else return no

    func is_closed(r:SocketResult -> Bool)
        when r is Closed return yes
        else return no

    func is_success(r:SocketResult -> Bool)
        when r is Success return yes
        else return no

enum SocketAccept(Ok(sock:TcpSocket), Timeout, Closed, Failure(reason:Text))
    func is_timeout(r:SocketAccept -> Bool)
        when r is Timeout return yes
        else return no

    func is_closed(r:SocketAccept -> Bool)
        when r is Closed return yes
        else return no

    func is_success(r:SocketAccept -> Bool)
        when r is Ok return yes
        else return no

enum SocketRecv(Ok(data:[Byte]), Timeout, Closed, Failure(reason:Text))
    func is_timeout(r:SocketRecv -> Bool)
        when r is Timeout return yes
        else return no

    func is_closed(r:SocketRecv -> Bool)
        when r is Closed return yes
        else return no

    func is_success(r:SocketRecv -> Bool)
        when r is Ok return yes
        else return no

struct RecvFrom(addr:SocketAddr, data:[Byte])

enum SocketRecvFrom(Ok(value:RecvFrom), Timeout, Closed, Failure(reason:Text))
    func is_timeout(r:SocketRecvFrom -> Bool)
        when r is Timeout return yes
        else return no

    func is_closed(r:SocketRecvFrom -> Bool)
        when r is Closed return yes
        else return no

    func is_success(r:SocketRecvFrom -> Bool)
        when r is Ok return yes
        else return no

enum SocketValue(Ok(value:Int), Failure(reason:Text))
    func is_success(r:SocketValue -> Bool)
        when r is Ok return yes
        else return no

enum SocketAddrResult(Ok(addr:SocketAddr), Failure(reason:Text))
    func is_success(r:SocketAddrResult -> Bool)
        when r is Ok return yes
        else return no

enum SocketOption(
    ReuseAddr,
    ReusePort,
    TcpNoDelay,
    KeepAlive,
    Broadcast,
    Ipv6V6Only,
    RecvBufSize,
    SendBufSize,
)

_socket_initialized := no

func _ensure_init()
    if _socket_initialized
        return
    err := Int32(0)
    status := C_code:Int32`ts_sock_init(&@err)`
    if status != C_code:Int32`TS_OK`
        fail("Socket init failed: $err")
    _socket_initialized = yes

func _family_to_af(family:SocketFamily -> Int32)
    when family is Inet return C_code:Int32`AF_INET`
    else return C_code:Int32`AF_INET6`

func _family_from_af(af:Int32 -> SocketFamily)
    if af == C_code:Int32`AF_INET6`
        return SocketFamily.Inet6
    return SocketFamily.Inet

func _sockopt_to_c(opt:SocketOption -> Int32)
    when opt is ReuseAddr return C_code:Int32`TS_SOCKOPT_REUSEADDR`
    is ReusePort return C_code:Int32`TS_SOCKOPT_REUSEPORT`
    is TcpNoDelay return C_code:Int32`TS_SOCKOPT_TCP_NODELAY`
    is KeepAlive return C_code:Int32`TS_SOCKOPT_KEEPALIVE`
    is Broadcast return C_code:Int32`TS_SOCKOPT_BROADCAST`
    is Ipv6V6Only return C_code:Int32`TS_SOCKOPT_IPV6_V6ONLY`
    is RecvBufSize return C_code:Int32`TS_SOCKOPT_RECV_BUF_SIZE`
    else return C_code:Int32`TS_SOCKOPT_SEND_BUF_SIZE`

func _err_text(err:Int32 -> Text)
    if err == 0
        return "unknown error"
    return C_code:Text`Text$from_str(strerror(@err))`

func _addr_err_text(err:Int32 -> Text)
    if err == 0
        return "unknown error"
    return C_code:Text`Text$from_str(ts_addr_strerror(@err))`

func _result_from_rc(rc:Int32, err:Int32 -> SocketResult)
    if rc == C_code:Int32`TS_OK` return SocketResult.Success
    if rc == C_code:Int32`TS_TIMEOUT` return SocketResult.Timeout
    if rc == C_code:Int32`TS_CLOSED` return SocketResult.Closed
    return SocketResult.Failure(_err_text(err))

struct SocketAddr(host:Text, port:Int, family:SocketFamily)
    func resolve(host:Text, port:Int, family=SocketFamily.Inet -> SocketAddrResult)
        _ensure_init()
        family_af := _family_to_af(family)
        service := Text(port)
        resolved_host : Text
        resolved_port_i64 := Int64(0)
        err := Int32(0)
        rc := C_code:Int32`
            struct ts_addr addr;
            char hostbuf[NI_MAXHOST];
            char servbuf[NI_MAXSERV];
            int status = TS_OK;

            if (ts_addr_resolve(Text$as_c_string(@host), Text$as_c_string(@service),
                @family_af, SOCK_STREAM, &addr, &@err) != TS_OK)
                status = TS_ERR;

            if (status == TS_OK && ts_addr_to_string(&addr, hostbuf, sizeof(hostbuf),
                servbuf, sizeof(servbuf), &@err) != TS_OK)
                status = TS_ERR;

            if (status == TS_OK) {
                @resolved_host = Text$from_str(hostbuf);
                @resolved_port_i64 = (int64_t)strtol(servbuf, NULL, 10);
            }
            status;
        `
        if rc == C_code:Int32`TS_OK`
            return SocketAddrResult.Ok(SocketAddr(resolved_host, Int(resolved_port_i64), family))
        return SocketAddrResult.Failure(_addr_err_text(err))

    func from_ip(ip:Text, port:Int, family=SocketFamily.Inet -> SocketAddrResult)
        return SocketAddr.resolve(ip, port, family=family)

struct TcpSocket(_handle:@Memory)
    func new(family=SocketFamily.Inet -> TcpSocket)
        _ensure_init()
        family_af := _family_to_af(family)
        err := Int32(0)
        handle : @Memory? = C_code:@Memory`
            struct ts_sock *s = GC_MALLOC(sizeof(*s));
            if (s != NULL) {
                memset(s, 0, sizeof(*s));
                if (ts_tcp_create(s, @family_af, &@err) != TS_OK)
                    s = NULL;
            }
            s;
        `
        if not handle
            fail("TcpSocket.new failed: $err")
        return TcpSocket(handle!)

    func connect(sock:TcpSocket, addr:SocketAddr, timeout_ms:Int=0 -> SocketResult)
        _ensure_init()
        family_af := _family_to_af(addr.family)
        service := Text(addr.port)
        err := Int32(0)
        addr_failed := no
        timeout_ms_i32 := Int32(timeout_ms)
        rc := C_code:Int32`
            struct ts_addr caddr;
            int status = TS_OK;
            if (ts_addr_resolve(Text$as_c_string(@(addr.host)), Text$as_c_string(@service),
                @family_af, SOCK_STREAM, &caddr, &@err) != TS_OK) {
                @addr_failed = 1;
                status = TS_ERR;
            }
            if (status == TS_OK)
                status = ts_sock_connect((struct ts_sock *)@(sock._handle), &caddr, @timeout_ms_i32, &@err);
            status;
        `
        if rc == C_code:Int32`TS_ERR` and addr_failed
            return SocketResult.Failure(_addr_err_text(err))
        return _result_from_rc(rc, err)

    func bind(sock:TcpSocket, addr:SocketAddr -> SocketResult)
        _ensure_init()
        family_af := _family_to_af(addr.family)
        service := Text(addr.port)
        err := Int32(0)
        addr_failed := no
        rc := C_code:Int32`
            struct ts_addr caddr;
            int status = TS_OK;
            if (ts_addr_resolve(Text$as_c_string(@(addr.host)), Text$as_c_string(@service),
                @family_af, SOCK_STREAM, &caddr, &@err) != TS_OK) {
                @addr_failed = 1;
                status = TS_ERR;
            }
            if (status == TS_OK)
                status = ts_sock_bind((struct ts_sock *)@(sock._handle), &caddr, &@err);
            status;
        `
        if rc == C_code:Int32`TS_ERR` and addr_failed
            return SocketResult.Failure(_addr_err_text(err))
        return _result_from_rc(rc, err)

    func listen(sock:TcpSocket, backlog=32 -> SocketResult)
        err := Int32(0)
        backlog_i32 := Int32(backlog)
        rc := C_code:Int32`
            ts_sock_listen((struct ts_sock *)@(sock._handle), @backlog_i32, &@err);
        `
        return _result_from_rc(rc, err)

    func getsockname(sock:TcpSocket -> SocketAddrResult)
        err := Int32(0)
        addr_text : Text
        addr_port_i64 := Int64(0)
        addr_family := Int32(0)
        addr_failed := no
        rc := C_code:Int32`
            struct ts_addr caddr;
            char hostbuf[NI_MAXHOST];
            char servbuf[NI_MAXSERV];
            int status = TS_OK;
            if (ts_sock_getsockname((struct ts_sock *)@(sock._handle), &caddr, &@err) != TS_OK)
                status = TS_ERR;
            if (status == TS_OK && ts_addr_to_string(&caddr, hostbuf, sizeof(hostbuf),
                servbuf, sizeof(servbuf), &@err) != TS_OK) {
                @addr_failed = 1;
                status = TS_ERR;
            }
            if (status == TS_OK) {
                @addr_text = Text$from_str(hostbuf);
                @addr_port_i64 = (int64_t)strtol(servbuf, NULL, 10);
                @addr_family = (int32_t)caddr.family;
            }
            status;
        `
        if rc == C_code:Int32`TS_OK`
            return SocketAddrResult.Ok(SocketAddr(addr_text, Int(addr_port_i64), _family_from_af(addr_family)))
        if addr_failed
            return SocketAddrResult.Failure(_addr_err_text(err))
        return SocketAddrResult.Failure(_err_text(err))

    func accept(sock:TcpSocket, timeout_ms:Int=0 -> SocketAccept)
        err := Int32(0)
        handle : @Memory?
        timeout_ms_i32 := Int32(timeout_ms)
        rc := C_code:Int32`
            struct ts_sock *c = GC_MALLOC(sizeof(*c));
            struct ts_addr peer;
            int status = TS_ERR;
            if (c == NULL) {
                @err = ENOMEM;
            } else {
                memset(c, 0, sizeof(*c));
                status = ts_sock_accept((struct ts_sock *)@(sock._handle), c, &peer,
                    @timeout_ms_i32, &@err);
                if (status == TS_OK)
                    @handle = c;
            }
            status;
        `
        if rc == C_code:Int32`TS_OK`
            return SocketAccept.Ok(TcpSocket(handle!))
        if rc == C_code:Int32`TS_TIMEOUT`
            return SocketAccept.Timeout
        if rc == C_code:Int32`TS_CLOSED`
            return SocketAccept.Closed
        return SocketAccept.Failure(_err_text(err))

    func send(sock:TcpSocket, data:[Byte], timeout_ms:Int=0 -> SocketResult)
        err := Int32(0)
        timeout_ms_i32 := Int32(timeout_ms)
        rc := C_code:Int32`
            size_t sent = 0;
            if (@data.stride != 1)
                List$compact(&@data, 1);
            ts_sock_send((struct ts_sock *)@(sock._handle), @data.data,
                (size_t)@data.length, @timeout_ms_i32, &sent, &@err);
        `
        return _result_from_rc(rc, err)

    func receive(sock:TcpSocket, max_bytes:Int=8192, timeout_ms:Int=0 -> SocketRecv)
        bytes : [Byte]
        err := Int32(0)
        max_bytes_i64 := Int64(max_bytes)
        timeout_ms_i32 := Int32(timeout_ms)
        rc := C_code:Int32`
            uint8_t *buf = GC_MALLOC((size_t)@max_bytes_i64);
            size_t got = 0;
            int status = ts_sock_recv((struct ts_sock *)@(sock._handle), buf,
                (size_t)@max_bytes_i64, @timeout_ms_i32, &got, &@err);
            if (status == TS_OK) {
                List$insert_all(&@bytes,
                    (List_t){.data = buf, .stride = 1, .length = (int64_t)got},
                    I(0), 1);
            }
            status;
        `
        if rc == C_code:Int32`TS_OK`
            return SocketRecv.Ok(bytes)
        if rc == C_code:Int32`TS_TIMEOUT`
            return SocketRecv.Timeout
        if rc == C_code:Int32`TS_CLOSED`
            return SocketRecv.Closed
        return SocketRecv.Failure(_err_text(err))

    func close(sock:TcpSocket -> SocketResult)
        err := Int32(0)
        rc := C_code:Int32`ts_sock_close((struct ts_sock *)@(sock._handle), &@err)`
        return _result_from_rc(rc, err)

    func set_option(sock:TcpSocket, option:SocketOption, value:Int -> SocketResult)
        err := Int32(0)
        opt_c := _sockopt_to_c(option)
        value_i32 := Int32(value)
        rc := C_code:Int32`
            ts_sock_set_sockopt((struct ts_sock *)@(sock._handle),
                @opt_c, @value_i32, &@err);
        `
        return _result_from_rc(rc, err)

    func get_option(sock:TcpSocket, option:SocketOption -> SocketValue)
        err := Int32(0)
        value := Int32(0)
        opt_c := _sockopt_to_c(option)
        rc := C_code:Int32`
            ts_sock_get_sockopt((struct ts_sock *)@(sock._handle),
                @opt_c, &@value, &@err);
        `
        if rc == C_code:Int32`TS_OK`
            return SocketValue.Ok(Int(value))
        return SocketValue.Failure(_err_text(err))

struct UdpSocket(_handle:@Memory)
    func new(family=SocketFamily.Inet -> UdpSocket)
        _ensure_init()
        family_af := _family_to_af(family)
        err := Int32(0)
        handle : @Memory? = C_code:@Memory`
            struct ts_sock *s = GC_MALLOC(sizeof(*s));
            if (s != NULL) {
                memset(s, 0, sizeof(*s));
                if (ts_udp_create(s, @family_af, &@err) != TS_OK)
                    s = NULL;
            }
            s;
        `
        if not handle
            fail("UdpSocket.new failed: $err")
        return UdpSocket(handle!)

    func bind(sock:UdpSocket, addr:SocketAddr -> SocketResult)
        _ensure_init()
        family_af := _family_to_af(addr.family)
        service := Text(addr.port)
        err := Int32(0)
        addr_failed := no
        rc := C_code:Int32`
            struct ts_addr caddr;
            int status = TS_OK;
            if (ts_addr_resolve(Text$as_c_string(@(addr.host)), Text$as_c_string(@service),
                @family_af, SOCK_DGRAM, &caddr, &@err) != TS_OK) {
                @addr_failed = 1;
                status = TS_ERR;
            }
            if (status == TS_OK)
                status = ts_sock_bind((struct ts_sock *)@(sock._handle), &caddr, &@err);
            status;
        `
        if rc == C_code:Int32`TS_ERR` and addr_failed
            return SocketResult.Failure(_addr_err_text(err))
        return _result_from_rc(rc, err)

    func connect(sock:UdpSocket, addr:SocketAddr, timeout_ms:Int=0 -> SocketResult)
        _ensure_init()
        family_af := _family_to_af(addr.family)
        service := Text(addr.port)
        err := Int32(0)
        addr_failed := no
        timeout_ms_i32 := Int32(timeout_ms)
        rc := C_code:Int32`
            struct ts_addr caddr;
            int status = TS_OK;
            if (ts_addr_resolve(Text$as_c_string(@(addr.host)), Text$as_c_string(@service),
                @family_af, SOCK_DGRAM, &caddr, &@err) != TS_OK) {
                @addr_failed = 1;
                status = TS_ERR;
            }
            if (status == TS_OK)
                status = ts_sock_connect((struct ts_sock *)@(sock._handle), &caddr, @timeout_ms_i32, &@err);
            status;
        `
        if rc == C_code:Int32`TS_ERR` and addr_failed
            return SocketResult.Failure(_addr_err_text(err))
        return _result_from_rc(rc, err)

    func getsockname(sock:UdpSocket -> SocketAddrResult)
        err := Int32(0)
        addr_text : Text
        addr_port_i64 := Int64(0)
        addr_family := Int32(0)
        addr_failed := no
        rc := C_code:Int32`
            struct ts_addr caddr;
            char hostbuf[NI_MAXHOST];
            char servbuf[NI_MAXSERV];
            int status = TS_OK;
            if (ts_sock_getsockname((struct ts_sock *)@(sock._handle), &caddr, &@err) != TS_OK)
                status = TS_ERR;
            if (status == TS_OK && ts_addr_to_string(&caddr, hostbuf, sizeof(hostbuf),
                servbuf, sizeof(servbuf), &@err) != TS_OK) {
                @addr_failed = 1;
                status = TS_ERR;
            }
            if (status == TS_OK) {
                @addr_text = Text$from_str(hostbuf);
                @addr_port_i64 = (int64_t)strtol(servbuf, NULL, 10);
                @addr_family = (int32_t)caddr.family;
            }
            status;
        `
        if rc == C_code:Int32`TS_OK`
            return SocketAddrResult.Ok(SocketAddr(addr_text, Int(addr_port_i64), _family_from_af(addr_family)))
        if addr_failed
            return SocketAddrResult.Failure(_addr_err_text(err))
        return SocketAddrResult.Failure(_err_text(err))

    func send(sock:UdpSocket, data:[Byte], timeout_ms:Int=0 -> SocketResult)
        err := Int32(0)
        timeout_ms_i32 := Int32(timeout_ms)
        rc := C_code:Int32`
            size_t sent = 0;
            if (@data.stride != 1)
                List$compact(&@data, 1);
            ts_sock_send((struct ts_sock *)@(sock._handle), @data.data,
                (size_t)@data.length, @timeout_ms_i32, &sent, &@err);
        `
        return _result_from_rc(rc, err)

    func send_to(sock:UdpSocket, addr:SocketAddr, data:[Byte], timeout_ms:Int=0 -> SocketResult)
        family_af := _family_to_af(addr.family)
        service := Text(addr.port)
        err := Int32(0)
        addr_failed := no
        timeout_ms_i32 := Int32(timeout_ms)
        rc := C_code:Int32`
            struct ts_addr caddr;
            size_t sent = 0;
            if (@data.stride != 1)
                List$compact(&@data, 1);
            int status = TS_OK;
            if (ts_addr_resolve(Text$as_c_string(@(addr.host)), Text$as_c_string(@service),
                @family_af, SOCK_DGRAM, &caddr, &@err) != TS_OK) {
                @addr_failed = 1;
                status = TS_ERR;
            }
            if (status == TS_OK)
                status = ts_sock_sendto((struct ts_sock *)@(sock._handle), @data.data,
                    (size_t)@data.length, &caddr, @timeout_ms_i32, &sent, &@err);
            status;
        `
        if rc == C_code:Int32`TS_ERR` and addr_failed
            return SocketResult.Failure(_addr_err_text(err))
        return _result_from_rc(rc, err)

    func receive(sock:UdpSocket, max_bytes:Int=8192, timeout_ms:Int=0 -> SocketRecv)
        bytes : [Byte]
        err := Int32(0)
        max_bytes_i64 := Int64(max_bytes)
        timeout_ms_i32 := Int32(timeout_ms)
        rc := C_code:Int32`
            uint8_t *buf = GC_MALLOC((size_t)@max_bytes_i64);
            size_t got = 0;
            int status = ts_sock_recv((struct ts_sock *)@(sock._handle), buf,
                (size_t)@max_bytes_i64, @timeout_ms_i32, &got, &@err);
            if (status == TS_OK) {
                List$insert_all(&@bytes,
                    (List_t){.data = buf, .stride = 1, .length = (int64_t)got},
                    I(0), 1);
            }
            status;
        `
        if rc == C_code:Int32`TS_OK`
            return SocketRecv.Ok(bytes)
        if rc == C_code:Int32`TS_TIMEOUT`
            return SocketRecv.Timeout
        if rc == C_code:Int32`TS_CLOSED`
            return SocketRecv.Closed
        return SocketRecv.Failure(_err_text(err))

    func receive_from(sock:UdpSocket, max_bytes:Int=8192, timeout_ms:Int=0 -> SocketRecvFrom)
        bytes : [Byte]
        addr_text : Text
        addr_port_i64 := Int64(0)
        addr_family := Int32(0)
        err := Int32(0)
        max_bytes_i64 := Int64(max_bytes)
        timeout_ms_i32 := Int32(timeout_ms)
        rc := C_code:Int32`
            struct ts_addr caddr;
            uint8_t *buf = GC_MALLOC((size_t)@max_bytes_i64);
            size_t got = 0;
            char hostbuf[NI_MAXHOST];
            char servbuf[NI_MAXSERV];
            int status = ts_sock_recvfrom((struct ts_sock *)@(sock._handle), buf,
                (size_t)@max_bytes_i64, &caddr, @timeout_ms_i32, &got, &@err);
            if (status == TS_OK && ts_addr_to_string(&caddr, hostbuf, sizeof(hostbuf),
                servbuf, sizeof(servbuf), &@err) != TS_OK)
                status = TS_ERR;
            if (status == TS_OK) {
                List$insert_all(&@bytes,
                    (List_t){.data = buf, .stride = 1, .length = (int64_t)got},
                    I(0), 1);
                @addr_text = Text$from_str(hostbuf);
                @addr_port_i64 = (int64_t)strtol(servbuf, NULL, 10);
                @addr_family = (int32_t)caddr.family;
            }
            status;
        `
        if rc == C_code:Int32`TS_OK`
            return SocketRecvFrom.Ok(RecvFrom(SocketAddr(addr_text, Int(addr_port_i64), _family_from_af(addr_family)), bytes))
        if rc == C_code:Int32`TS_TIMEOUT`
            return SocketRecvFrom.Timeout
        if rc == C_code:Int32`TS_CLOSED`
            return SocketRecvFrom.Closed
        return SocketRecvFrom.Failure(_err_text(err))

    func close(sock:UdpSocket -> SocketResult)
        err := Int32(0)
        rc := C_code:Int32`ts_sock_close((struct ts_sock *)@(sock._handle), &@err)`
        return _result_from_rc(rc, err)

    func set_option(sock:UdpSocket, option:SocketOption, value:Int -> SocketResult)
        err := Int32(0)
        opt_c := _sockopt_to_c(option)
        value_i32 := Int32(value)
        rc := C_code:Int32`
            ts_sock_set_sockopt((struct ts_sock *)@(sock._handle),
                @opt_c, @value_i32, &@err);
        `
        return _result_from_rc(rc, err)

    func get_option(sock:UdpSocket, option:SocketOption -> SocketValue)
        err := Int32(0)
        value := Int32(0)
        opt_c := _sockopt_to_c(option)
        rc := C_code:Int32`
            ts_sock_get_sockopt((struct ts_sock *)@(sock._handle),
                @opt_c, &@value, &@err);
        `
        if rc == C_code:Int32`TS_OK`
            return SocketValue.Ok(Int(value))
        return SocketValue.Failure(_err_text(err))

func socket_or_fail(r:SocketResult, message:Text?=none)
    if not r.is_success()
        fail(message or "Socket error: $r")

func socket_accept_or_fail(r:SocketAccept, message:Text?=none -> TcpSocket)
    when r is Ok(sock)
        return sock
    else fail(message or "Socket accept error: $r")

func socket_recv_or_fail(r:SocketRecv, message:Text?=none -> [Byte])
    when r is Ok(data)
        return data
    else fail(message or "Socket receive error: $r")

func socket_recvfrom_or_fail(r:SocketRecvFrom, message:Text?=none -> RecvFrom)
    when r is Ok(value)
        return value
    else fail(message or "Socket receive_from error: $r")

func socket_value_or_fail(r:SocketValue, message:Text?=none -> Int)
    when r is Ok(value)
        return value
    else fail(message or "Socket value error: $r")

func socket_addr_or_fail(r:SocketAddrResult, message:Text?=none -> SocketAddr)
    when r is Ok(addr)
        return addr
    else fail(message or "Socket address error: $r")

enum SelectItem(Tcp(sock:TcpSocket), 
                Udp(sock:UdpSocket))

enum SelectResult(Ready(read:[SelectItem], 
                        write:[SelectItem]), 
                        Timeout, Failure(reason:Text))

func tcp(sock:TcpSocket -> SelectItem)
    return SelectItem.Tcp(sock)

func udp(sock:UdpSocket -> SelectItem)
    return SelectItem.Udp(sock)

func select_tcp(read:[TcpSocket]=[], write:[TcpSocket]=[], timeout_ms:Int=0 -> SelectResult)
    read_items := [tcp(sock) for sock in read]
    write_items := [tcp(sock) for sock in write]
    return select(read_items, write_items, timeout_ms=timeout_ms)

func select_udp(read:[UdpSocket]=[], write:[UdpSocket]=[], timeout_ms:Int=0 -> SelectResult)
    read_items := [udp(sock) for sock in read]
    write_items := [udp(sock) for sock in write]
    return select(read_items, write_items, timeout_ms=timeout_ms)

func _zero_bytes(count:Int -> [Byte])
    bytes : [Byte]
    if count <= 0
        return bytes
    count_i64 := Int64(count)
    C_code`
        uint8_t *buf = GC_MALLOC((size_t)@count_i64);
        memset(buf, 0, (size_t)@count_i64);
        List$insert_all(&@bytes,
            (List_t){.data = buf, .stride = 1, .length = (int64_t)@count_i64},
            I(0), 1);
    `
    return bytes

func select(read:[SelectItem]=[], write:[SelectItem]=[], timeout_ms:Int=0 -> SelectResult)
    read_handles : @[ @Memory ] = @[]
    write_handles : @[ @Memory ] = @[]

    for item in read
        when item is Tcp(sock)
            read_handles.insert(sock._handle)
        is Udp(sock)
            read_handles.insert(sock._handle)

    for item in write
        when item is Tcp(sock)
            write_handles.insert(sock._handle)
        is Udp(sock)
            write_handles.insert(sock._handle)

    read_len := read_handles[].length
    write_len := write_handles[].length
    read_ready := _zero_bytes(read_len)
    write_ready := _zero_bytes(write_len)
    err := Int32(0)
    timeout_ms_i32 := Int32(timeout_ms)
    read_count_i32 := Int32(read_len)
    write_count_i32 := Int32(write_len)

    read_handles_value := read_handles[]
    write_handles_value := write_handles[]
    rc := C_code:Int32`
        List$compact(&@read_handles_value, sizeof(void *));
        List$compact(&@write_handles_value, sizeof(void *));
        ts_select((struct ts_sock **)@read_handles_value.data, @read_count_i32,
            (struct ts_sock **)@write_handles_value.data, @write_count_i32,
            @timeout_ms_i32, &@err,
            (uint8_t *)@read_ready.data, (uint8_t *)@write_ready.data);
    `

    if rc == C_code:Int32`TS_TIMEOUT`
        return SelectResult.Timeout
    if rc != C_code:Int32`TS_OK`
        return SelectResult.Failure(_err_text(err))

    read_ready_items : @[SelectItem] = @[]
    for i,item in read
        if (read_ready[i] or Byte(0)) != 0
            read_ready_items.insert(item)

    write_ready_items : @[SelectItem] = @[]
    for i,item in write
        if (write_ready[i] or Byte(0)) != 0
            write_ready_items.insert(item)

    return SelectResult.Ready(read_ready_items[], write_ready_items[])
