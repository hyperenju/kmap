obj-m = kmap.o
DEFAULT_MAP = "capslock:leftctrl,leftctrl:capslock,zenhan:esc"

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

install:
	cp kmap.ko /lib/modules/$(shell uname -r)/
	depmod
	modprobe kmap default_map=$(DEFAULT_MAP)

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
