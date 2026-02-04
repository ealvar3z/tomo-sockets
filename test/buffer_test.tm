use pthreads
use ../sockets.tm

func main()
    say("RUN buffer")

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
        socket_or_fail(client.send("one\n".utf8(), timeout_ms=2000), "tcp send failed")
        socket_or_fail(client.send("two\nthree".utf8(), timeout_ms=2000), "tcp send failed")
        socket_or_fail(client.close(), "tcp close failed")
    )

    client_sock := socket_accept_or_fail(server.accept(timeout_ms=2000), "tcp accept failed")
    buf : @SocketBuffer = SocketBuffer.new(@client_sock)
    line1 := socket_recv_or_fail(buf.receive_line(timeout_ms=2000), "line1 failed")
    text1 := Text.from_utf8(line1) or fail("FAIL: invalid utf8")
    assert text1 == "one"

    line2 := socket_recv_or_fail(buf.receive_line(timeout_ms=2000), "line2 failed")
    text2 := Text.from_utf8(line2) or fail("FAIL: invalid utf8")
    assert text2 == "two"

    rest := socket_recv_or_fail(buf.receive_all(timeout_ms=2000), "receive_all failed")
    text3 := Text.from_utf8(rest) or fail("FAIL: invalid utf8")
    assert text3 == "three"

    socket_or_fail(client_sock.close(), "tcp client close failed")
    socket_or_fail(server.close(), "tcp server close failed")
    client_thread.join()

    say("PASS buffer")
