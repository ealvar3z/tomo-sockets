use pthreads
use ../sockets.tm

func main()
    server := TcpSocket.new()
    socket_or_fail(server.bind(SocketAddr("127.0.0.1", 0, SocketFamily.Inet)), "bind failed")
    socket_or_fail(server.listen(), "listen failed")
    server_addr := socket_addr_or_fail(server.getsockname(), "getsockname failed")

    client_thread := PThread.new(func()
        client := TcpSocket.new()
        socket_or_fail(
            client.connect(SocketAddr("127.0.0.1", server_addr.port, SocketFamily.Inet), timeout_ms=2000),
            "connect failed"
        )
        socket_or_fail(client.send("hello".utf8(), timeout_ms=2000), "send failed")
        socket_or_fail(client.close(), "client close failed")
    )

    client_sock := socket_accept_or_fail(server.accept(timeout_ms=2000), "accept failed")
    recv_bytes := socket_recv_or_fail(client_sock.receive(timeout_ms=2000), "receive failed")
    recv_text := Text.from_utf8(recv_bytes) or fail("invalid utf8")
    say("server received: $recv_text")

    socket_or_fail(client_sock.close(), "close failed")
    socket_or_fail(server.close(), "close failed")
    client_thread.join()
