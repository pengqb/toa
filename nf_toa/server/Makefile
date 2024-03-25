obj-m	+= nf_toa.o

ifeq ($(KERNDIR), )
KDIR	:= /lib/modules/4.19.90-2301.6.0.0186.0.231016.x86_64/build
else
KDIR	:= /lib/modules/4.19.90-2301.6.0.0186.0.231016.x86_64/build
endif
PWD	:= $(shell pwd)

ifeq ($(DEBUG), 1)
ccflags-y += -g -O0
endif

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	gcc -o server server.c


clean:
	$(MAKE) -C $(KDIR) M=$(PWD) modules clean
	-rm -rf server

install:
	if [ -d "$(INSDIR)" ]; then \
		install -m 664 nf_toa.ko $(INSDIR)/nf_toa.ko; \
	fi