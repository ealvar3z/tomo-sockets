use ../sockets.tm

func main()
    recv_sock := UdpSocket.new()
    socket_or_fail(recv_sock.bind(SocketAddr("127.0.0.1", 0, SocketFamily.Inet)), "bind failed")
    recv_addr := socket_addr_or_fail(recv_sock.getsockname(), "getsockname failed")

    send_sock := UdpSocket.new()
    socket_or_fail(
        send_sock.send_to(SocketAddr("127.0.0.1", recv_addr.port, SocketFamily.Inet), "hello-udp".utf8(), timeout_ms=2000),
        "send_to failed"
    )

    result := recv_sock.receive_from(timeout_ms=2000)
    when result is Ok(value)
        text := Text.from_utf8(value.data) or fail("invalid utf8")
        say("received from $value.addr.host:$value.addr.port: $text")
    is Timeout
        fail("timeout")
    is Closed
        fail("closed")
    else
        fail("receive error")

    socket_or_fail(send_sock.close(), "send close failed")
    socket_or_fail(recv_sock.close(), "recv close failed")
