import io
import sys
import struct
import math

# -------------------------- 核心读取函数（适配原函数逻辑） --------------------------
def read_uint8(bio):
    """读取1字节无符号整数（原函数的unsigned __int8）"""
    b = bio.read(1)
    if not b:
        raise EOFError("Unexpected EOF when reading uint8")
    return struct.unpack("<B", b)[0]

def read_uint16(bio):
    """读取2字节小端无符号整数"""
    b = bio.read(2)
    if len(b) < 2:
        raise EOFError("Unexpected EOF when reading uint16")
    return struct.unpack("<H", b)[0]

def read_uint32(bio):
    """读取4字节小端无符号整数"""
    b = bio.read(4)
    if len(b) < 4:
        raise EOFError("Unexpected EOF when reading uint32")
    return struct.unpack("<I", b)[0]

def read_leb128(bio):
    """
    适配原函数的无符号LEB128解码（对应sub_180023B40）
    原函数中所有容器长度（列表/字典/集合）均使用此编码
    """
    result = 0
    shift = 0
    while True:
        byte_val = read_uint8(bio)
        # 取低7位，左移累加
        result |= (byte_val & 0x7F) << shift
        # 最高位为0则结束（原函数的LEB128规则）
        if not (byte_val & 0x80):
            break
        shift += 7
        # 防止溢出（原函数的安全校验）
        if shift > 63:
            raise OverflowError("LEB128 integer too large")
    return result

def read_utf8_style_int(bio):
    """
    适配原函数G/g分支的变长整数解码（UTF-8风格的整数编码）
    对应原函数中：
    v81 = v80 & 0x7F;
    if (v80 >= 0x80u) { 循环读取后续字节，低7位累加 }
    """
    result = 0
    shift = 0
    while True:
        byte_val = read_uint8(bio)
        # 取当前字节的低7位
        result += (byte_val & 0x7F) << shift
        # 最高位为0则结束
        if not (byte_val & 0x80):
            break
        shift += 7
    return result

# -------------------------- 核心解码函数（严格对齐原函数case） --------------------------
def decode_blob(bio):
    """
    适配原函数sub_180022A80的核心解码逻辑
    返回：(解码后的对象, 处理后的字节流指针位置)
    """
    # 读取标记字节（原函数v4 = *a3）
    type_byte = read_uint8(bio)
    type_char = chr(type_byte)
    current_pos = bio.tell()

    # -------------------------- 基础类型 --------------------------
    if type_char == 'n':
        # Py_None (原函数case 'n')
        return None, current_pos
    elif type_char == 't':
        # Py_True (原函数case 't')
        return True, current_pos
    elif type_char == 'F':
        # Py_False (原函数case 'F')
        return False, current_pos
    elif type_char in ('a', 'u'):
        # 字符串/Unicode：strlen后指针到末尾+1（原函数v101 = v99; v7 = &v3[v101 + 1]）
        bs = b""
        while True:
            c = bio.read(1)
            if c == b"\x00" or not c:
                break
            bs += c
        # 原函数要求指针移动到字符串长度+1（跳过末尾的0）
        bio.seek(current_pos + len(bs) + 1)
        return bs.decode("utf-8", errors="surrogatepass"), bio.tell()
    elif type_char == 'w':
        # 单字符字符串：读取1字节（原函数case 'w'）
        c = bio.read(1)
        if not c:
            raise EOFError("Unexpected EOF for 'w' type")
        bio.seek(current_pos + 1)
        return c.decode("utf-8", errors="surrogatepass"), bio.tell()
    elif type_char == 'l' or type_char == 'q':
        # 整数：l=正数，q=负数（原函数case 'l'/'q'）
        value = read_leb128(bio)
        if type_char == 'q':
            value = -value
        return value, bio.tell()
    elif type_char in ('G', 'g'):
        # 特殊变长整数（原函数case 'G'/'g'）
        count = read_leb128(bio)
        total = 0
        for _ in range(count):
            # 读取UTF-8风格的整数段
            num = read_utf8_style_int(bio)
            total = (total << 1) + num
        # G标记需要设置第2位标志（原函数*(v74 + 16) |= 2uLL）
        if type_char == 'G':
            return (total, "G_FLAG"), bio.tell()
        return total, bio.tell()
    # -------------------------- 容器类型 --------------------------
    elif type_char == 'T':
        # 元组：LEB128读长度，递归解码元素（原函数case 'T'）
        sub_count = read_leb128(bio)
        elements = []
        for _ in range(sub_count):
            elem, _ = decode_blob(bio)
            elements.append(elem)
        return tuple(elements), bio.tell()
    elif type_char == 'L':
        # 列表：LEB128读长度，递归解码元素（原函数case 'L'）
        list_count = read_leb128(bio)
        elements = []
        for _ in range(list_count):
            elem, _ = decode_blob(bio)
            elements.append(elem)
        return elements, bio.tell()
    elif type_char == 'D':
        # 字典：LEB128读长度，交替解码key/value（原函数case 'D'）
        dict_count = read_leb128(bio)
        o = {}
        for _ in range(dict_count):
            key, _ = decode_blob(bio)
            value, _ = decode_blob(bio)
            o[key] = value
        return o, bio.tell()
    elif type_char == 'S' or type_char == 'P':
        # 集合/冻结集合（原函数case 'S'/'P'）
        set_count = read_leb128(bio)
        elements = []
        for _ in range(set_count):
            elem, _ = decode_blob(bio)
            elements.append(elem)
        if type_char == 'S':
            return set(elements), bio.tell()
        else:
            return frozenset(elements), bio.tell()
    # -------------------------- 字节/字符串类型 --------------------------
    elif type_char == 'B':
        # 字节数组：LEB128读长度，读取指定字节（原函数case 'B'）
        length = read_leb128(bio)
        bs = bio.read(length)
        if len(bs) < length:
            raise EOFError(f"Expected {length} bytes for 'B' type, got {len(bs)}")
        return bytearray(bs), bio.tell()
    elif type_char == 'c':
        # 字节字符串：strlen后指针到末尾+1（原函数case 'c'）
        bs = b""
        while True:
            c = bio.read(1)
            if c == b"\x00" or not c:
                break
            bs += c
        # 原函数v7 = &v3[v93 + 1]
        bio.seek(current_pos + len(bs) + 1)
        return bs, bio.tell()
    elif type_char == 'b':
        # 字节字符串：LEB128读长度（原函数case 'b'）
        length = read_leb128(bio)
        bs = bio.read(length)
        if len(bs) < length:
            raise EOFError(f"Expected {length} bytes for 'b' type, got {len(bs)}")
        return bs, bio.tell()
    # -------------------------- 浮点数/复数 --------------------------
    elif type_char == 'd':
        # 预定义浮点数索引（原函数case 'd'）
        index = read_uint8(bio)
        # 原函数v94 = (48LL * *v3 + PyRuntime + 10720LL)
        return f"<PREDEFINED_FLOAT_INDEX_{index}>", bio.tell()
    elif type_char == 'f':
        # 浮点数：读取8字节双精度（原函数case 'f'，v7 = a3 + 9）
        float_bytes = bio.read(8)
        if len(float_bytes) < 8:
            raise EOFError("Expected 8 bytes for 'f' type float")
        o = struct.unpack('<d', float_bytes)[0]
        bio.seek(current_pos + 8)  # 原函数指针移动8字节
        return o, bio.tell()
    elif type_char == 'j':
        # 复数：读取16字节（8+8）（原函数case 'j'，v7 = a3 + 17）
        real_bytes = bio.read(8)
        imag_bytes = bio.read(8)
        if len(real_bytes) < 8 or len(imag_bytes) < 8:
            raise EOFError("Expected 16 bytes for 'j' type complex")
        real = struct.unpack('<d', real_bytes)[0]
        imag = struct.unpack('<d', imag_bytes)[0]
        bio.seek(current_pos + 16)  # 原函数指针移动16字节
        return complex(real, imag), bio.tell()
    elif type_char == 'Z':
        # 预定义特殊浮点数（原函数case 'Z'）
        index = read_uint8(bio)
        # 映射原函数的特殊浮点数（NaN/正负无穷）
        z_map = {
            0: math.nan,
            1: -math.inf,
            2: math.inf,
            3: -math.nan,  # 带符号NaN
            4: math.nan,   # 带符号NaN
            5: -math.inf   # 扩展索引
        }
        o = z_map.get(index, f"<PREDEFINED_DOUBLE_INDEX_{index}>")
        bio.seek(current_pos + 1)
        return o, bio.tell()
    # -------------------------- 特殊对象/操作 --------------------------
    elif type_char == 'M':
        # 匿名对象（原函数case 'M'）
        anon_type = read_uint8(bio)
        anon_map = {
            0: None,  # Py_None
            1: Ellipsis,  # PyEllipsis_Type
            2: NotImplemented,  # Py_NotImplementedStruct
            3: "<PyFunction_Type>",
            4: "<PyGen_Type>",
            5: "<PyCFunction_Type>",
            6: "<PyCode_Type>",
            7: "<PyModule_Type>",
            0x0A: "<qword_1800422B8>"  # 补充原函数的0x0A分支
        }
        o = anon_map.get(anon_type, f"<ANON_TYPE_{anon_type}>")
        bio.seek(current_pos + 1)
        return o, bio.tell()
    elif type_char == 'O':
        # 动态属性获取（原函数case 'O'）
        attr_name = b""
        while True:
            c = bio.read(1)
            if c == b"\x00" or not c:
                break
            attr_name += c
        # 原函数while (*v7++); 指针移动到末尾+1
        bio.seek(current_pos + len(attr_name) + 1)
        return f"<DYNAMIC_ATTR_GET:{attr_name.decode('utf-8')}>", bio.tell()
    elif type_char == 'Q':
        # 特殊值（原函数case 'Q'）
        special_type = read_uint8(bio)
        special_map = {
            0: Ellipsis,  # Ellipsis
            1: NotImplemented,  # NotImplemented
            2: "<SELF_REFERENCE>"
        }
        o = special_map.get(special_type, f"<SPECIAL_VALUE_{special_type}>")
        bio.seek(current_pos + 1)
        return o, bio.tell()
    elif type_char == 'X':
        # 字节偏移：读取长度后返回指针（原函数case 'X'）
        skip_length = read_leb128(bio)
        # 原函数return &v121[v120]; 移动指针但不创建对象
        bio.seek(current_pos + skip_length)
        return f"<SKIPPED_{skip_length}_BYTES>", bio.tell()
    elif type_char == 'C':
        # 代码对象（原函数case 'C'）
        version = read_leb128(bio)
        argcount = read_leb128(bio)
        flags = read_leb128(bio)
        return f"<CODE_OBJECT_VERSION_{version}_ARGCOUNT_{argcount}_FLAGS_{flags}>", bio.tell()
    elif type_char == 'A':
        # 泛型别名（原函数case 'A'）
        origin, _ = decode_blob(bio)
        args, _ = decode_blob(bio)
        return f"<GENERIC_ALIAS_ORIGIN_{origin}_ARGS_{args}>", bio.tell()
    elif type_char == ';':
        # Lambda表达式（原函数case ';'）
        code_obj, _ = decode_blob(bio)
        defaults, _ = decode_blob(bio)
        closure, _ = decode_blob(bio)
        return f"<LAMBDA_CODE_{code_obj}_DEFAULTS_{defaults}_CLOSURE_{closure}>", bio.tell()
    elif type_char == ':':
        # 切片对象（原函数case ':'）
        start, _ = decode_blob(bio)
        stop, _ = decode_blob(bio)
        step, _ = decode_blob(bio)
        return slice(start, stop, step), bio.tell()
    elif type_char == 'p':
        # 堆栈引用（原函数case 'p'）
        return "<STACK_REFERENCE_PREV>", current_pos
    elif type_char == 'v':
        # 变长UTF-8字符串（原函数case 'v'）
        length = read_leb128(bio)
        string_bytes = bio.read(length)
        if len(string_bytes) < length:
            raise EOFError(f"Expected {length} bytes for 'v' type string")
        return string_bytes.decode('utf-8', errors="surrogatepass"), bio.tell()
    elif type_char == 's':
        # 驻留UTF-8字符串（原函数case 's'）
        # 原函数PyUnicode_DecodeUTF8(v3, 0LL, "surrogatepass")
        bs = b""
        while True:
            c = bio.read(1)
            if c == b"\x00" or not c:
                break
            bs += c
        return bs.decode('utf-8', errors="surrogatepass"), bio.tell()
    elif type_char == 'H':
        # 原函数case 'H'：特殊处理（补充适配）
        sub_obj, _ = decode_blob(bio)
        return f"<SPECIAL_H_TYPE_{sub_obj}>", bio.tell()
    elif type_char == '.':
        # 原函数错误分支：Missing blob values
        raise ValueError("Missing blob values (case '.')")
    else:
        # 原函数默认分支：abort()
        raise ValueError(f"Missing decoding for type 0x{type_byte:02X} ('{type_char}')")

# -------------------------- 主函数（适配原函数的blob解析流程） --------------------------
def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary_file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    with open(file_path, "rb") as f_in:
        bs = f_in.read()
    bio = io.BytesIO(bs)

    # 读取头部（原函数的hash和size）
    try:
        hash_ = read_uint32(bio)
        size = read_uint32(bio)
        print(f"Blob Header - Hash: 0x{hash_:08X}, Size: 0x{size:08X}")
    except EOFError as e:
        print(f"Error reading header: {e}")
        sys.exit(1)

    # 解析blob内容（对齐原函数的循环逻辑）
    while bio.tell() < size:
        # 读取blob名称（以0结尾）
        blob_name = b""
        while True:
            c = bio.read(1)
            if c == b"\x00" or not c:
                break
            blob_name += c
        blob_name = blob_name.decode("utf-8", errors="replace")

        # 读取blob大小和计数
        try:
            blob_size = read_uint32(bio)
            blob_count = read_uint16(bio)
        except EOFError as e:
            print(f"Error reading blob metadata for '{blob_name}': {e}")
            break

        print(f"\nDecoding blob '{blob_name}' (Size: 0x{blob_size:08X}, Count: {blob_count})...")
        
        if blob_name == "__main__":
            # 解码__main__ blob的内容
            decoded = []
            for idx in range(blob_count):
                try:
                    obj, new_pos = decode_blob(bio)
                    decoded.append(obj)
                    print(f"  [{idx}]: {obj}")
                except (EOFError, ValueError) as e:
                    print(f"  [{idx}]: Decode error - {e}")
                    break
            break
        else:
            # 跳过其他blob（原函数的指针移动逻辑）
            skip_bytes = blob_size - 2  # 减去已读的blob_count（2字节）
            bio.seek(bio.tell() + skip_bytes)
            print(f"  Skipped (non __main__ blob)")

if __name__ == "__main__":
    main()