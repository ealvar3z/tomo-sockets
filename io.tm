use <gc.h>
use <string.h>

use ./lib/sockets.h

struct SelectRaw(rc:Int32, err:Int32, read_ready:[Byte], write_ready:[Byte])

func _zero_bytes(count:Int -> [Byte])
    bytes : [Byte]
    if count <= 0
        return bytes
    count_i64 := Int64(count)
    C_code`
        uint8_t *buf = GC_MALLOC((size_t)@count_i64);
        memset(buf, 0, (size_t)@count_i64);
        List$insert_all(&@bytes,
            (List_t){.data = buf, .stride = 1, .length = (int64_t)@count_i64},
            I(0), 1);
    `
    return bytes

func select_raw(read_handles:@[@Memory], write_handles:@[@Memory], timeout_ms:Int=0 -> SelectRaw)
    read_len := read_handles[].length
    write_len := write_handles[].length
    read_ready := _zero_bytes(read_len)
    write_ready := _zero_bytes(write_len)
    err := Int32(0)
    timeout_ms_i32 := Int32(timeout_ms)
    read_count_i32 := Int32(read_len)
    write_count_i32 := Int32(write_len)

    read_handles_value := read_handles[]
    write_handles_value := write_handles[]
    rc := C_code:Int32`
        List$compact(&@read_handles_value, sizeof(void *));
        List$compact(&@write_handles_value, sizeof(void *));
        ts_select((struct ts_sock **)@read_handles_value.data, @read_count_i32,
            (struct ts_sock **)@write_handles_value.data, @write_count_i32,
            @timeout_ms_i32, &@err,
            (uint8_t *)@read_ready.data, (uint8_t *)@write_ready.data);
    `

    return SelectRaw(rc, err, read_ready, write_ready)
