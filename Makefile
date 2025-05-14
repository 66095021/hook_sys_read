obj-m := blocker.o
blocker-objs +=  main.o net.o
COMPILE_DIR=$(PWD)
KDIR = /lib/modules/$(shell uname -r)/build
EXTRA_CFLAGS='-save-temps'
all:
	$(MAKE) -C $(KDIR) M=$(COMPILE_DIR) modules

clean:
	rm -f -v *.o *.ko
