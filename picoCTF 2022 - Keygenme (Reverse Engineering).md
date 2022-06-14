# picoCTF 2022 - Keygenme (Reverse Engineering)

## Details

**Event**: picoCTF 2022  
**Challenge**: Keygenme  
**Points**: 400  
**Category**: Reverse Engineering  
**Author**: LT 'syreal' Jones  
**Tags**: Reverse Engineering, binary, keygen  
**Status**: Completed  
**Date**: 19/03/2022  

## Description

> Can you get the flag?  
>  
> Reverse engineer this [binary](https://artifacts.picoctf.net/c/515/keygenme).

## Walkthrough

First thing I noticed was that the name suggests that this is a task that should require a keygen to crack...  
So I fired up Ghidra and loaded the binary and, after some name modifications, I got the following `main` function:

```c
int main(void) {
  bool validKey;
  long in_FS_OFFSET;
  char input [40];
  long mem;
  
  mem = *(long *)(in_FS_OFFSET + 40);
  printf("Enter your license key: ");
  fgets(input,37,stdin);
  validKey = verifyKey(input);
  if (validKey == false) {
    puts("That key is invalid.");
  }
  else {
    puts("That key is valid.");
  }
  if (mem != *(long *)(in_FS_OFFSET + 40)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

The code reveals that the first I/O action is a request for a license key, in which the user must insert the key that is then verified through the `verifyKey` function, that receives the entered key and returns a boolean response (*true* or *false*) depending if the key is valid or not.  
The next logic thing to do is to analyse the `verifyKey` function, to check if we can crack what should be the key.  
Once again, after some renaming and improvements on the reversed code, I got the following code from the `verifyKey`:  

```c
bool verifyKey(char *input) {
  bool valid;
  size_t length;
  long in_FS_OFFSET;
  int index;
  int i;
  int j;
  int k;
  int l;
  undefined2 key_p6;
  byte local_b8 [16];
  byte local_a8 [16];
  undefined8 key_p1;
  undefined8 key_p2;
  undefined8 key_p3;
  undefined4 key_p4;
  char local_78 [12];
  undefined local_6c;
  undefined local_66;
  undefined local_5f;
  undefined local_5e;
  char local_58 [32];
  char stack [40];
  long mem;
  
  mem = *(long *)(in_FS_OFFSET + 40);
  key_p1 = 0x7b4654436f636970;
  key_p2 = 0x30795f676e317262;
  key_p3 = 0x6b5f6e77305f7275;
  key_p4 = 0x5f7933;
  key_p6 = L'}';
  length = strlen((char *)&key_p1);
  MD5((uchar *)&key_p1,length,local_b8);
  length = strlen((char *)&key_p6);
  MD5((uchar *)&key_p6,length,local_a8);
  index = 0;
  for (i = 0; i < 16; i = i + 1) {
    sprintf(local_78 + index,"%02x",(uint)local_b8[i]);
    index = index + 2;
  }
  index = 0;
  for (j = 0; j < 16; j = j + 1) {
    sprintf(local_58 + index,"%02x",(uint)local_a8[j]);
    index = index + 2;
  }
  for (k = 0; k < 27; k = k + 1) {
    stack[k] = *(char *)((long)&key_p1 + (long)k);
  }
  stack[27] = local_66;
  stack[28] = local_5e;
  stack[29] = local_5f;
  stack[30] = local_78[0];
  stack[31] = local_5e;
  stack[32] = local_66;
  stack[33] = local_6c;
  stack[34] = local_5e;
  stack[35] = (undefined)key_p6;
  length = strlen(input);
  if (length == 36) {
    for (l = 0; l < 36; l = l + 1) {
      if (input[l] != stack[l]) {
        valid = false;
        goto exit;
      }
    }
    valid = true;
  }
  else {
    valid = false;
  }
exit:
  if (mem != *(long *)(in_FS_OFFSET + 40)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return valid;
}
```

Ghidra divided the supposed key array in portions... all the key parts except the fifth, are decoded to `picoCTF{br1ng_y0ur_0wn_k3y_????????}`, where the `????????` is the unknown part of the key. We need to try and understand what should be replaced by those characters.  
By analyzing the code, there are several ways to do this:

- Bruteforce our way through, by providing the following charset `0123456789abcdef` to a bruteforce tool, or develop our own, and constantly change (randomly or incrementally) each unknown character, because those are the available characters in the MD5 hashing.
- Reconstruct the keygenme program but instead of verifying the input, print the `stack` contents to the stdout.
- Debug the program and analyze what's being compared when entering the last `verifyKey`'s for loop.

I started by writting a python script that would bruteforce the key, while I was trying the other solutions. The script ran for hours (while I was afk) but didn't find the correct key, so I stopped the script and decided to go for the last option.

I used GDB to debug the program and found that the main function would start at `0x55555555548b`.  
I noticed the `strlen` function is called right before the loop that compares each character starts, so I decided to put a breakpoint on every `strlen` call, and tried to understand the assembly code after the last `strlen` call is done (which is the one before the key comparison).  
When we get there, we find the following assembly code, which we can relate to the decompiled code (on Ghidra), as shown in the comments below:

```gdb
   0x555555555411                  mov    rdi, rax                                      
   0x555555555414                  call   0x5555555550e0 <strlen@plt>                # Get the given input size
●  0x555555555419                  cmp    rax, 0x24                                  # Compare the given input size with the actual key size (if it's equal to 24h, 36 in decimal)
 → 0x55555555541d                  je     0x555555555426	TAKEN [Reason: Z]        # The beggining of the for loop
   ↳  0x555555555426                  mov    DWORD PTR [rbp-0xb8], 0x0               # Start the iterator (i = 0)
      0x555555555430                  jmp    0x555555555467
      0x555555555432                  mov    eax, DWORD PTR [rbp-0xb8]
      0x555555555438                  movsxd rdx, eax
      0x55555555543b                  mov    rax, QWORD PTR [rbp-0xd8]
      0x555555555442                  add    rax, rdx
```

After a few steps we encounter the comparator at `0x555555555455`, which compares the character from the given input at index `i`, with the character from the actual key at index `i`.

```gdb
$rax   : 0x39              
$rbx   : 0x00555555555520  →   endbr64 
$rcx   : 0x1               
$rdx   : 0x41              
$rsp   : 0x007fffffffdd80  →  0x0000000000000000
$rbp   : 0x007fffffffde60  →  0x007fffffffdeb0  →  0x0000000000000000
$rsi   : 0x00555555556008  →   add BYTE PTR [rbp+0x6e], al
$rdi   : 0x20              
$rip   : 0x00555555555455  →   cmp dl, al
$r8    : 0x0               
$r9    : 0x007fffffffdb16  →  0xbdd7adfea006663 ("cf"?)
$r10   : 0xcf              
$r11   : 0x0               
$r12   : 0x00555555555120  →   endbr64 
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffdd80│+0x0000: 0x0000000000000000	 ← $rsp
0x007fffffffdd88│+0x0008: 0x007fffffffde80  →  "picoCTF{br1ng_y0ur_0wn_k3y_AAAAAAAA}"
0x007fffffffdd90│+0x0010: 0x007ffff7cab4a0  →  0x0000000000000000
0x007fffffffdd98│+0x0018: 0x00001000000020 (" "?)
0x007fffffffdda0│+0x0020: 0x0000001b00000010
0x007fffffffdda8│+0x0028: 0x007d7fff0000001b
0x007fffffffddb0│+0x0030: 0x6201e972d5188243
0x007fffffffddb8│+0x0038: 0x8238d4c7bb1c98d0
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555448                  mov    eax, DWORD PTR [rbp-0xb8]
   0x55555555544e                  cdqe   
   0x555555555450                  movzx  eax, BYTE PTR [rbp+rax*1-0x30]
●→ 0x555555555455                  cmp    dl, al
   0x555555555457                  je     0x555555555460
   0x555555555459                  mov    eax, 0x0
   0x55555555545e                  jmp    0x555555555475
   0x555555555460                  add    DWORD PTR [rbp-0xb8], 0x1
   0x555555555467                  cmp    DWORD PTR [rbp-0xb8], 0x23
```

The snippet above is validating **the first character from the unknown part of the key**.  
So now, I deleted unnecessary breakpoints and only had the following ones:

```gdb
gef➤  info b
Num     Type           Disp Enb Address            What
2       breakpoint     keep y   0x000055555555548b 
	breakpoint already hit 1 time
9       breakpoint     keep y   0x0000555555555455 
```


As we can see, the **RAX** register contains the correct character and the **RDX** contains the given input's character. Since I provided `picoCTF{br1ng_y0ur_0wn_k3y_AAAAAAAA}` as the input, the **RDX** contains `41h`, which is translated to `A` according to the ASCII table. If we also translate the **RAX** value, we find that the first unknown value should be `9`.  
If we continue with the previous thought, we can find the correct key.  
To find the next character we should execute program again, but replacing the previous unknown characeter by the right one. By doing that, the program will iterate until the next comparison, giving us the next correct character that should be in the key, and the cycle continues until the last character from the key (`}`).  
By doing this, we find the following stream of characters, that represents the previously unknown part of the key: `9d74d90d`. Also, by using this input, the program returns the following message: `That key is valid.`.  
This means we cracked it! That should be the flag to submit on the picoCTF platform.

## Flag

*picoCTF{br1ng_y0ur_0wn_k3y_9d74d90d}*
