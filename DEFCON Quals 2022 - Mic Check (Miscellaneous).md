# DEFCON Quals 2022 - Mic Check (Miscellaneous)

## Details

**Event**: Defcon Quals 2022  
**Challenge**: Mic Check  
**Points**: Dynamic  
**Category**: Miscellaneous  
**Author**: Alexander Taylor (fuzyll)  
**Tags**: -----  
**Status**: Completed  
**Date**: 27/05/2022  

## Description

Some challenges, like this one, will require you to connect to a remote server and interact with it. Connect to on port 31337, receive the prompt from the service, send back the required input, and then receive the response. If you provided the right input, the flag will be in the response.

Note that these challenges usually have a server-side timeout on connections. This one is pretty forgiving, but others won't be. We highly recommend automating your interactions with this challenge because future ones will require it.

[simple-service-c45xrrmhuc5su.shellweplayaga.me:31337](simple-service-c45xrrmhuc5su.shellweplayaga.me:31337)

(Source code: <https://github.com/Nautilus-Institute/quals-2022/blob/main/simple-service/challenge/simple-service.c>)

## Walkthrough

This program is only available remotely (at the time of the challenge no source code was provided or available), so I ran the connection to the desired address and port and got the following prompt: `Ticket please:`. This probably isn't part of the actual program (could be part of a shellscript that verifies the ticket and then runs the actual program).  
After sending the ticket, we get an output like the following: `1645 + 13054 = `. After a small time the program returns `Time's up!` and exits.  
I believed it was supposed to send the result of that math expression. The numbers are randomly generated so the result is "never" the same. I also noticed the expression would always be a sum.  
So I decided to write the following script that would receive the numbers to sum up and send the result back to the host fast, retrieving, then, the flag:

```py
from pwn import *

#Connect to server
s = remote("simple-service-c45xrrmhuc5su.shellweplayaga.me", 31337)

# Send ticket to host
ticket = "ticket{SternSteerage2987n22:Ylq63Kjuxj7ZxxULpPeMSLNC2fi3JF1e68s-U0Xq0ykqGgYk}"
log.info("TICKET: " + ticket)
print(s.recv().decode())
print("Sending ticket...")
s.sendline(str.encode(ticket))

# Get math expression, calculate and send the result
mat = s.recv().decode()
log.info("EXPRESSION: " + mat)
calc = mat.split(" ")
res = int(calc[0]) + int(calc[2])
log.info("RESULT:" + str(res))
s.sendline(str.encode(str(res)))

# Get flag
print(s.recv().decode())

s.interactive()
```

After executing the script, the following output is returned:

```pwn
TICKET: ticket{SternSteerage2987n22:Ylq63Kjuxj7ZxxULpPeMSLNC2fi3JF1e68s-U0Xq0ykqGgYk}
Ticket please:
Sending ticket...
EXPRESSION: 19755 + 13442 =
RESULT: 33197
Correct!
Here's your flag:flag{good_job_this_is_the_flag}
```

## Flag

*flag{good_job_this_is_the_flag}*
