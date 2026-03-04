import io
import struct
 
def read_uint32(bio):
    return struct.unpack("<I", bio.read(4))[0]
 
def read_uint16(bio):
    return struct.unpack("<H", bio.read(2))[0]
 
def read_utf8(bio):
    bs = b""
 
    while True:
        bs += bio.read(1)
        if b"\x00" in bs:
            break
    return bs[:-1].decode("utf-8")
 
def main():
    with open("main.bin", "rb") as f_in:
        bs = f_in.read()
 
    bio = io.BytesIO(bs)
    hash_ = read_uint32(bio)
    size = read_uint32(bio)
    print(f"hash: {hex(hash_)}")
    print(f"size: {hex(size)}")
 
    while bio.tell() < size:
        blob_name = read_utf8(bio)
        blob_size = read_uint32(bio)
        blob_count = read_uint16(bio)
        print(f"name: {blob_name}, size: {hex(blob_size)}, count: {hex(blob_count)}")
        bio.seek(bio.tell() + (blob_size - 2))
 
if __name__ == "__main__":
    main()