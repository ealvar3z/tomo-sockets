use <stdlib.h>
use <unistd.h>

use ../sockets.tm

test_root := (/tmp/tomo-sockets-tls-test)
cert_path := test_root ++ (./cert.pem)
key_path := test_root ++ (./key.pem)
pid_path := test_root ++ (./server.pid)
port := 19443

func run_or_fail(cmd:Text)
    rc := C_code:Int32`system(Text$as_c_string(@cmd))`
    fail("command failed ($rc): $cmd") unless rc == 0

func run_no_fail(cmd:Text)
    _ := C_code:Int32`system(Text$as_c_string(@cmd))`

func sleep_ms(ms:Int)
    ms_i64 := Int64(ms)
    C_code`usleep((useconds_t)(@ms_i64 * 1000));`

func setup_tls_materials()
    run_or_fail("mkdir -p $test_root")
    run_or_fail("openssl req -x509 -newkey rsa:2048 -nodes -keyout $key_path -out $cert_path -days 1 -subj '/CN=localhost' >/dev/null 2>&1")

func start_tls_server()
    run_or_fail("sh -c 'openssl s_server -quiet -accept $port -cert $cert_path -key $key_path -www > $test_root/server.log 2>&1 & sleep 0.1; pgrep -f \"openssl s_server -quiet -accept $port\" | head -n1 > $pid_path'")
    sleep_ms(300)

func stop_tls_server()
    pid_text := (pid_path.read() or "").trim(" \n\t")
    if pid_text != ""
        run_no_fail("kill $pid_text >/dev/null 2>&1 || true")
    run_no_fail("rm -f $pid_path")

func tls_connect(config:TlsConfig -> TlsSocket)
    sock := TcpSocket.new()
    socket_or_fail(
        sock.connect(SocketAddr("127.0.0.1", port, SocketFamily.Inet), timeout_ms=2000),
        "tcp connect failed"
    )
    return tls_socket_or_fail(TlsSocket.wrap_client(sock, config=config), "tls wrap failed")

func test_tls_handshake_and_io()
    say("RUN tls handshake+io")
    sock := tls_connect(TlsConfig(server_name="localhost", verify_peer=no, insecure_skip_verify=yes))
    tls_or_fail(sock.handshake(timeout_ms=2000), "tls handshake failed")

    req := "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".utf8()
    tls_or_fail(sock.send(req, timeout_ms=2000), "tls send failed")
    recv := sock.receive(timeout_ms=2000)
    when recv is Ok(data)
        text := Text.from_utf8(data) or fail("invalid utf8 from tls server")
        assert text.has("HTTP/")
    is Timeout
        fail("FAIL: tls receive timeout")
    is Closed
        fail("FAIL: tls closed unexpectedly")
    else
        fail("FAIL: tls receive error")
    tls_or_fail(sock.close(), "tls close failed")
    say("PASS tls handshake+io")

func test_tls_receive_timeout()
    say("RUN tls receive timeout")
    sock := tls_connect(TlsConfig(server_name="localhost", verify_peer=no, insecure_skip_verify=yes))
    tls_or_fail(sock.handshake(timeout_ms=2000), "tls handshake failed")
    recv := sock.receive(timeout_ms=50)
    when recv is Timeout
        pass
    else
        fail("FAIL: expected tls receive timeout, got $recv")
    tls_or_fail(sock.close(), "tls close failed")
    say("PASS tls receive timeout")

func test_tls_untrusted_cert_failure()
    say("RUN tls untrusted cert failure")
    sock := tls_connect(TlsConfig(server_name="localhost", verify_peer=yes, insecure_skip_verify=no))
    result := sock.handshake(timeout_ms=2000)
    when result is Failure(_)
        pass
    else
        fail("FAIL: expected tls verify failure, got $result")
    _ := sock.close()
    say("PASS tls untrusted cert failure")

func test_tls_hostname_mismatch_failure()
    say("RUN tls hostname mismatch failure")
    sock := tls_connect(
        TlsConfig(
            server_name="wrong-host.local",
            verify_peer=yes,
            insecure_skip_verify=no,
            ca_file=cert_path
        )
    )
    result := sock.handshake(timeout_ms=2000)
    when result is Failure(_)
        pass
    else
        fail("FAIL: expected hostname mismatch failure, got $result")
    _ := sock.close()
    say("PASS tls hostname mismatch failure")

func main()
    say("RUN tls")
    setup_tls_materials()
    start_tls_server()
    do
        test_tls_handshake_and_io()
        test_tls_receive_timeout()
        test_tls_untrusted_cert_failure()
        test_tls_hostname_mismatch_failure()
    stop_tls_server()
    say("PASS tls")
