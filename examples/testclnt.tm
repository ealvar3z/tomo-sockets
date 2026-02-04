use ../sockets.tm

host := "127.0.0.1"
port := 8383

func _remote(sock:TcpSocket, buf:@SocketBuffer, command:Text)
    socket_or_fail(sock.send((command ++ "\n").utf8(), timeout_ms=2000), "send failed")
    recv := buf.receive_line(timeout_ms=2000)
    when recv is Ok(_)
        pass
    else
        fail("server did not ack: $recv")

func main()
    say("client: connecting...")
    control := TcpSocket.new()
    socket_or_fail(
        control.connect(SocketAddr(host, port, SocketFamily.Inet), timeout_ms=2000),
        "connect failed"
    )
    buf := SocketBuffer.new(@control)

    _remote(control, buf, "first line")
    _remote(control, buf, "second line")
    _remote(control, buf, "third line")

    socket_or_fail(control.close(), "close failed")
    say("client: done")
