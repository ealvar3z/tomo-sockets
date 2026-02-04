use pthreads
use ../sockets.tm

func main()
    say("RUN select")

    server := TcpSocket.new()
    socket_or_fail(server.bind(SocketAddr("127.0.0.1", 0, SocketFamily.Inet)), "tcp bind failed")
    socket_or_fail(server.listen(), "tcp listen failed")
    server_addr := socket_addr_or_fail(server.getsockname(), "tcp getsockname failed")

    client_thread := PThread.new(func()
        client := TcpSocket.new()
        socket_or_fail(
            client.connect(SocketAddr("127.0.0.1", server_addr.port, SocketFamily.Inet), timeout_ms=2000),
            "tcp connect failed"
        )
        socket_or_fail(client.send("select".utf8(), timeout_ms=2000), "tcp send failed")
        socket_or_fail(client.close(), "tcp close failed")
    )

    ready := select_tcp(read=[server], timeout_ms=2000)
    when ready is Ready(read, _)
        assert read.length == 1
    is Timeout
        fail("FAIL: select tcp timeout")
    else
        fail("FAIL: select tcp error")

    client_sock := socket_accept_or_fail(server.accept(timeout_ms=2000), "tcp accept failed")
    recv_bytes := socket_recv_or_fail(client_sock.receive(timeout_ms=2000), "tcp receive failed")
    recv_text := Text.from_utf8(recv_bytes) or fail("FAIL: tcp receive invalid utf8")
    assert recv_text == "select"
    socket_or_fail(client_sock.close(), "tcp client close failed")
    socket_or_fail(server.close(), "tcp server close failed")
    client_thread.join()
    say("PASS select tcp")

    udp_recv := UdpSocket.new()
    socket_or_fail(udp_recv.bind(SocketAddr("127.0.0.1", 0, SocketFamily.Inet)), "udp bind failed")
    udp_addr := socket_addr_or_fail(udp_recv.getsockname(), "udp getsockname failed")

    udp_send := UdpSocket.new()
    socket_or_fail(
        udp_send.send_to(SocketAddr("127.0.0.1", udp_addr.port, SocketFamily.Inet), "udp".utf8(), timeout_ms=2000),
        "udp send_to failed"
    )

    ready_udp := select_udp(read=[udp_recv], timeout_ms=2000)
    when ready_udp is Ready(read, _)
        assert read.length == 1
    is Timeout
        fail("FAIL: select udp timeout")
    else
        fail("FAIL: select udp error")

    recv_from := udp_recv.receive_from(timeout_ms=2000)
    when recv_from is Ok(value)
        text := Text.from_utf8(value.data) or fail("FAIL: udp receive invalid utf8")
        assert text == "udp"
    is Timeout
        fail("FAIL: udp receive timeout")
    is Closed
        fail("FAIL: udp receive closed")
    else
        fail("FAIL: udp receive error")

    socket_or_fail(udp_send.close(), "udp send close failed")
    socket_or_fail(udp_recv.close(), "udp recv close failed")
    say("PASS select udp")
    say("PASS select")
