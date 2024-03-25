#KERNEL_VER = $(shell uname -r)
KERNEL_VER = 4.19.90-2301.6.0.0186.0.231016.x86_64

# the file to compile
obj-m := nf_to_add.o

modules-objs:= myhook.o    

# specify flags for the module compilation
EXTRA_CFLAGS = -g -O0

build: kernel_modules

kernel_modules:
	make -C /lib/modules/$(KERNEL_VER)/build M=$(PWD) modules
	gcc -o client client.c

clean:
	make -C /lib/modules/$(KERNEL_VER)/build M=$(PWD) clean
	-rm -rf client