#obj-m += seedFilter.o
#obj-m += seedPrint.o
obj-m += seedBlock.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

ins:
	sudo dmesg -C
	sudo insmod seedFilter.ko
	sudo insmod seedPrint.ko
	sudo insmod seedBlock.ko

rm:
	sudo rmmod seedFilter
	sudo rmmod seedPrint
	sudo rmmod seedBlock

