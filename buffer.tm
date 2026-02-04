use ./sockets.tm

ascii_newline := Byte(10)

struct SocketBuffer(sock:@TcpSocket, data:@[Byte]=@[])
    func new(sock:@TcpSocket -> @SocketBuffer)
        return @SocketBuffer(sock)

    func is_empty(buf:SocketBuffer -> Bool)
        return buf.available() == 0

    func available(buf:SocketBuffer -> Int)
        return buf.data[].length

    func clear(buf:@SocketBuffer)
        buf.data = @[]

    func _append(buf:@SocketBuffer, chunk:[Byte])
        buf.data.insert_all(chunk)

    func _line_from_buffer(buf:@SocketBuffer -> [Byte]?)
        data := buf.data[]
        data_len := Int(data.length)
        if data_len == 0
            return none
        for i in Int(1).to(data_len)
            if data[i] == ascii_newline
                line : [Byte] = []
                if i > 1
                    line = data.to(i - 1)
                if i == data_len
                    buf.clear()
                else
                    rest := data.from(i + 1)
                    buf.data = @rest
                return line
        return none

    func receive_n(buf:@SocketBuffer, n:Int, timeout_ms:Int=0 -> SocketRecv)
        if n <= 0
            return SocketRecv.Ok([])

        while buf.available() < n
            recv := buf.sock[].receive(max_bytes=8192, timeout_ms=timeout_ms)
            when recv is Ok(data)
                buf._append(data)
            is Timeout
                return SocketRecv.Timeout
            is Closed
                break
            else
                return SocketRecv.Failure(recv.Failure!.reason)

        if buf.available() == 0
            return SocketRecv.Closed

        take := n
        if take > buf.available()
            take = buf.available()

        data := buf.data[]
        out := data.to(take)
        if take == Int(data.length)
            buf.clear()
        else
            rest := data.from(take + 1)
            buf.data = @rest
        return SocketRecv.Ok(out)

    func receive_line(buf:@SocketBuffer, timeout_ms:Int=0 -> SocketRecv)
        repeat
            if line := buf._line_from_buffer()
                return SocketRecv.Ok(line)

            recv := buf.sock[].receive(max_bytes=8192, timeout_ms=timeout_ms)
            when recv is Ok(data)
                if data.length == 0
                    return SocketRecv.Closed
                buf._append(data)
            is Timeout
                return SocketRecv.Timeout
            is Closed
                if buf.available() == 0
                    return SocketRecv.Closed
                data := buf.data[]
                buf.clear()
                return SocketRecv.Ok(data)
            else
                return SocketRecv.Failure(recv.Failure!.reason)
        return SocketRecv.Failure("Unreachable")

    func receive_all(buf:@SocketBuffer, timeout_ms:Int=0 -> SocketRecv)
        repeat
            recv := buf.sock[].receive(max_bytes=8192, timeout_ms=timeout_ms)
            when recv is Ok(data)
                if data.length == 0
                    break
                buf._append(data)
            is Timeout
                return SocketRecv.Timeout
            is Closed
                break
            else
                return SocketRecv.Failure(recv.Failure!.reason)

        if buf.available() == 0
            return SocketRecv.Closed
        data := buf.data[]
        buf.clear()
        return SocketRecv.Ok(data)
