use pthreads
use colorful
use patterns
use ../sockets.tm

use <unistd.h>

struct IrcLine(prefix:Text?, command:Text, params:[Text], trailing:Text?)
ui_enabled := no

func ui_init()
    ui_enabled = C_code:Bool`isatty(1)`

func ui_done()
    pass

func ui_info(text:Text)
    if ui_enabled
        $Colorful"@(cyan,bold:[info]) $text".print()
    else
        say("[info] $text")

func ui_warn(text:Text)
    if ui_enabled
        $Colorful"@(yellow,bold:[warn]) $text".print()
    else
        say("[warn] $text")

func ui_recv(text:Text)
    if ui_enabled
        $Colorful"@(green:$text)".print()
    else
        say(text)

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

func send_line_tcp(sock:@TcpSocket, line:Text)
    payload := (line ++ "\r\n").utf8()
    socket_or_fail(sock[].send(payload, timeout_ms=2000), "send failed")

func send_line_tls(sock:@TlsSocket, line:Text)
    payload := (line ++ "\r\n").utf8()
    tls_or_fail(sock[].send(payload, timeout_ms=2000), "send failed")

func handle_input_tcp(sock:@TcpSocket, line:Text, channel:Text?=none, quitting:@Bool -> Bool)
    if line == ""
        return yes
    if line == "/quit"
        socket_or_fail(sock[].send("QUIT :client exiting\r\n".utf8(), timeout_ms=2000), "send failed")
        quitting[] = yes
        return no
    if line.starts_with("/")
        send_line_tcp(sock, line.without_prefix("/"))
        return yes
    if ch := channel
        send_line_tcp(sock, "PRIVMSG $ch :$line")
        return yes
    send_line_tcp(sock, line)
    return yes

func handle_input_tls(sock:@TlsSocket, line:Text, channel:Text?=none, quitting:@Bool -> Bool)
    if line == ""
        return yes
    if line == "/quit"
        tls_or_fail(sock[].send("QUIT :client exiting\r\n".utf8(), timeout_ms=2000), "send failed")
        quitting[] = yes
        return no
    if line.starts_with("/")
        send_line_tls(sock, line.without_prefix("/"))
        return yes
    if ch := channel
        send_line_tls(sock, "PRIVMSG $ch :$line")
        return yes
    send_line_tls(sock, line)
    return yes

func start_input_thread_tcp(sock:@TcpSocket, quitting:@Bool, channel:Text?=none -> PThread)
    return PThread.new(func()
        if lines := (/dev/stdin).by_line()
            for line in lines
                keep_running := handle_input_tcp(sock, line, channel=channel, quitting=quitting)
                if not keep_running
                    break
        else
            say("stdin unavailable")
    )

func start_input_thread_tls(sock:@TlsSocket, quitting:@Bool, channel:Text?=none -> PThread)
    return PThread.new(func()
        if lines := (/dev/stdin).by_line()
            for line in lines
                keep_running := handle_input_tls(sock, line, channel=channel, quitting=quitting)
                if not keep_running
                    break
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
    tls|t:Bool=no,
    verbose|v:Bool=no
)
    ui_init()
    ui_info("commands: /quit, /join <#channel>, /part <#channel>, /msg <target> <text>")

    sock := TcpSocket.new()
    if verbose
        ui_info("connecting to $host:$port...")
    socket_or_fail(
        sock.connect(SocketAddr(host, port, SocketFamily.Inet), timeout_ms=5000),
        "connect failed"
    )

    if verbose
        ui_info("connected")

    quitting := @no

    if tls
        tls_config := TlsConfig(server_name=host)
        tls_sock := tls_socket_or_fail(TlsSocket.wrap_client(sock, config=tls_config), "TLS wrap failed")
        tls_or_fail(tls_sock.handshake(timeout_ms=5000), "TLS handshake failed")
        if verbose
            negotiated_alpn := tls_sock.selected_alpn() or "<none>"
            ui_info("TLS handshake complete (ALPN=$negotiated_alpn)")

        if pass_text := password
            send_line_tls(@tls_sock, "PASS $pass_text")
        send_line_tls(@tls_sock, "NICK $nick")
        send_line_tls(@tls_sock, "USER $user 0 * :$realname")
        if ch := channel
            send_line_tls(@tls_sock, "JOIN $ch")

        buf := TlsBuffer.new(@tls_sock)
        input_thread := start_input_thread_tls(@tls_sock, quitting, channel=channel)
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
                ui_recv(line)
                if quitting[]
                    break
                irc := parse_irc(line)
                if irc.command == "PING"
                    token := irc.trailing or (irc.params[-1] or "")
                    if token != ""
                        send_line_tls(@tls_sock, "PONG :$token")
                    else
                        send_line_tls(@tls_sock, "PONG")
            is Timeout
                if quitting[]
                    break
                continue
            is Closed
                ui_info("connection closed")
                break
            else
                fail("receive error: $recv")

        tls_or_fail(tls_sock.close(), "close failed")
    else
        if pass_text := password
            send_line_tcp(@sock, "PASS $pass_text")
        send_line_tcp(@sock, "NICK $nick")
        send_line_tcp(@sock, "USER $user 0 * :$realname")
        if ch := channel
            send_line_tcp(@sock, "JOIN $ch")

        buf := SocketBuffer.new(@sock)
        input_thread := start_input_thread_tcp(@sock, quitting, channel=channel)
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
                ui_recv(line)
                if quitting[]
                    break
                irc := parse_irc(line)
                if irc.command == "PING"
                    token := irc.trailing or (irc.params[-1] or "")
                    if token != ""
                        send_line_tcp(@sock, "PONG :$token")
                    else
                        send_line_tcp(@sock, "PONG")
            is Timeout
                if quitting[]
                    break
                continue
            is Closed
                ui_info("connection closed")
                break
            else
                fail("receive error: $recv")

        socket_or_fail(sock.close(), "close failed")

    if quitting[]
        ui_warn("disconnected")
    ui_done()
