use pthreads
use ../sockets.tm

struct IrcLine(prefix:Text?, 
               command:Text, 
               params:[Text], 
               trailing:Text?)

func strip_cr(line:Text -> Text)
    if line.ends_with("\r")
        return line.without_suffix("\r")
    return line

func parse_irc(line:Text -> IrcLine)
    prefix : Text? = none
    rest := line
    if rest.starts_with(":")
        if space := rest.find(" ")
            prefix = rest.slice(from=2, to=space - 1)
            rest = rest.slice(from=space + 1)
        else
            return IrcLine(rest.slice(from=2), rest.slice(from=2), [], none)

    trailing : Text? = none
    if idx := rest.find(" :")
        trailing = rest.slice(from=idx + 2)
        rest = rest.slice(to=idx - 1)

    parts := rest.split_any()
    if parts.length == 0
        return IrcLine(prefix, "", [], trailing)

    command := parts[1]!
    params : [Text] = []
    if parts.length > 1
        params = parts.from(2)
    return IrcLine(prefix, command, params, trailing)

func send_line(sock:@TcpSocket, line:Text)
    payload := (line ++ "\r\n").utf8()
    socket_or_fail(sock[].send(payload, timeout_ms=2000), "send failed")

func handle_input(sock:@TcpSocket, line:Text, channel:Text?=none)
    if line == ""
        return
    if line == "/quit"
        send_line(sock, "QUIT :client exiting")
        socket_or_fail(sock[].close(), "close failed")
        return
    if line.starts_with("/")
        send_line(sock, line.without_prefix("/"))
        return
    if ch := channel
        send_line(sock, "PRIVMSG $ch :$line")
        return
    send_line(sock, line)

func start_input_thread(sock:@TcpSocket, channel:Text?=none -> PThread)
    return PThread.new(func()
        if lines := (/dev/stdin).by_line()
            for line in lines
                handle_input(sock, line, channel=channel)
        else
            say("stdin unavailable")
    )

func main(
    nick:Text="tomoaki",
    host:Text="irc.libera.chat",
    port:Int=6667,
    user:Text="tomo",
    realname:Text="Tomo User",
    password:Text?=none,
    channel:Text?=none,
    verbose|v:Bool=no
)
    sock := TcpSocket.new()
    if verbose
        say("connecting to $host:$port...")
    socket_or_fail(
        sock.connect(SocketAddr(host, port, SocketFamily.Inet), timeout_ms=5000),
        "connect failed"
    )

    if verbose
        say("connected")

    if pass_text := password
        send_line(@sock, "PASS $pass_text")
    send_line(@sock, "NICK $nick")
    send_line(@sock, "USER $user 0 * :$realname")
    if ch := channel
        send_line(@sock, "JOIN $ch")

    buf := SocketBuffer.new(@sock)
    input_thread := start_input_thread(@sock, channel=channel)
    input_thread.detatch()

    while yes
        recv := buf.receive_line(timeout_ms=1000)
        when recv is Ok(bytes)
            if bytes.length == 0
                continue
            text := Text.from_utf8(bytes) or "<binary>"
            line := strip_cr(text)
            if line == ""
                continue
            say(line)
            irc := parse_irc(line)
            if irc.command == "PING"
                token := irc.trailing or (irc.params[-1] or "")
                if token != ""
                    send_line(@sock, "PONG :$token")
                else
                    send_line(@sock, "PONG")
        is Timeout
            continue
        is Closed
            say("connection closed")
            break
        else
            fail("receive error: $recv")

    socket_or_fail(sock.close(), "close failed")
