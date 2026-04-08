# CTF Writeup: Reverse Engineering Hash Validation 

##  Challenge Overview

We are given a binary (`system.out`) that simulates an account setup and login system. The program:

1. Prompts for a password  
2. Asks for the password length  
3. Displays stored password bytes  
4. Requests a **hash** to authenticate  
5. If correct, attempts to read `flag.txt`  

Goal: Compute the correct hash and bypass authentication.

##  Initial Analysis

###  Basic Enumeration

terminal:
file system.out
strings system.out

From strings, we observe:

Please set a password for your account:
How many bytes in length is your password?
Enter your hash to access your account!
flag.txt

This indicates the program internally computes a hash and compares it with user input.

### Program Behavior
Please set a password for your account:
hello
How many bytes in length is your password?
5
Your successfully stored password:
104 101 108 108 111 10 ...
Enter your hash to access your account!

Key Observations
	• Output shows ASCII values of input
	• 104 101 108 108 111 → "hello"
	• 10 → newline (\n)

### Reverse Engineering the Hash Function
Disassembling the hash function reveals:
shl $0x5        ; multiply by 32
add             ; + original value → total = *33
add char        ; add current byte

Interpretation:
This translates to:
hash = hash * 33 + char;

### Reconstructing the Hash

Code:
input="hello\n" //hello was my input string
unsigned long hash = 5381;

for each character c in input:
    hash = hash * 33 + c;

Output: Hash=15237662580160011234

## Flag
picoCTF{d0nt_trust_us3rs}