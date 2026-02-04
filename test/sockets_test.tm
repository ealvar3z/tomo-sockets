use pthreads
use ../sockets.tm

func main()
    say("RUN sockets")
    # TCP echo
    server := TcpSocket.new()
    socket_or_fail(server.bind(SocketAddr("127.0.0.1", 0, SocketFamily.Inet)), "tcp bind failed")
    socket_or_fail(server.listen(), "tcp listen failed")
    server_addr := socket_addr_or_fail(server.getsockname(), "tcp getsockname failed")

    payload := "ping".utf8()

    client_thread := PThread.new(func()
        client := TcpSocket.new()
        socket_or_fail(
            client.connect(SocketAddr("127.0.0.1", server_addr.port, SocketFamily.Inet), timeout_ms=2000),
            "tcp connect failed"
        )
        socket_or_fail(client.send(payload, timeout_ms=2000), "tcp send failed")
        socket_or_fail(client.close(), "tcp close failed")
    )

    client_sock := socket_accept_or_fail(server.accept(timeout_ms=2000), "tcp accept failed")
    recv_bytes := socket_recv_or_fail(client_sock.receive(timeout_ms=2000), "tcp receive failed")
    recv_text := Text.from_utf8(recv_bytes) or fail("FAIL: tcp receive invalid utf8")
    assert recv_text == "ping"
    socket_or_fail(client_sock.close(), "tcp client close failed")
    socket_or_fail(server.close(), "tcp server close failed")
    client_thread.join()
    say("PASS tcp")

    # UDP receive_from
    udp_recv := UdpSocket.new()
    socket_or_fail(udp_recv.bind(SocketAddr("127.0.0.1", 0, SocketFamily.Inet)), "udp bind failed")
    udp_addr := socket_addr_or_fail(udp_recv.getsockname(), "udp getsockname failed")

    udp_send := UdpSocket.new()
    send_result := udp_send.send_to(
        SocketAddr("127.0.0.1", udp_addr.port, SocketFamily.Inet),
        "pong".utf8(),
        timeout_ms=2000
    )
    socket_or_fail(send_result, "udp send_to failed")

    recv_from := udp_recv.receive_from(timeout_ms=2000)
    when recv_from is Ok(value)
        text := Text.from_utf8(value.data) or fail("FAIL: udp receive invalid utf8")
        assert text == "pong"
        assert value.addr.port > 0
    is Timeout
        fail("FAIL: udp receive timeout")
    is Closed
        fail("FAIL: udp receive closed")
    else
        fail("FAIL: udp receive error")

    socket_or_fail(udp_send.close(), "udp send close failed")
    socket_or_fail(udp_recv.close(), "udp recv close failed")
    say("PASS udp")
    say("PASS sockets")
