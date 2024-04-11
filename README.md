
# rdmem

**rdmem** is a Linux kernel module enabling remapping and reading of the hardware address space of the processor into kernel virtual memory. Memory can be read through the /dev/rdmem interface in userspace.

**rdmem/lkm/rdmem.c** - kernel module.   
**rdmem/rdmem/rdmem.c** - userspace application for reading data from /dev/rdmem device file.

Example reads SAM9N12's *General Purpose Backup Register* peripheral (hw address 0xFFFFFE60):

    $ rdmem -a 0xFFFFFE60 -s 20 -b 32
    Options: address=0x00000000FFFFFE60 size=20 read=B32.
    0102.0304 0506.0708 0910.1112 1314.15AA
    0000.0000
    ---------
    $ cat /proc/iomem
    fffff800-fffff9ff : fffff800.gpio gpio@fffff800
    fffffa00-fffffbff : fffffa00.gpio gpio@fffffa00
    fffffe00-fffffe0f : fffffe00.reset-controller reset-controller@fffffe00
    fffffe60-fffffe73 : rdmem
    $
