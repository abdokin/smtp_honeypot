# How To Auth 
### create test credential in base64
```
    echo -n '\x00username\x00password' | base64 
```
#### connect using telnet 
```
    telnet localhost 25
```
### sending Auth command 
```
    AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk 
```
