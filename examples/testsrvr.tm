use sockets

host := "127.0.0.1"
port := 8383

func main()
    server := TcpSocket.new()
    socket_or_fail(server.bind(SocketAddr(host, port, SocketFamily.Inet)), "bind failed")
    socket_or_fail(server.listen(), "listen failed")
    ack := "\n".utf8()

    while yes
        say("server: waiting for client connection...")
        conn := socket_accept_or_fail(server.accept(), "accept failed")
        buf := SocketBuffer.new(@conn)

        while yes
            recv := buf.receive_line()
            when recv is Ok(line)
                socket_or_fail(conn.send(ack), "send ack failed")
                text := Text.from_utf8(line) or "<binary>"
                say(text)
            is Timeout
                continue
            is Closed
                socket_or_fail(conn.close(), "close failed")
                break
            else
                socket_or_fail(conn.close(), "close failed")
                break
