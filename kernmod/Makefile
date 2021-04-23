# obj-m += lkm_example.o

# all:
# 	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

# clean:
# 	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

obj-m +=mydumbkernelfilemodule.o
obj-m +=binaryblobtest.o
obj-m +=attempt1.o
#obj-m +=oldattempt1.o
KDIR =//usr/src/linux-headers-4.19.0-14-amd64

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	rm -rf *.o *.ko *.mod.* *.symvers *.order
