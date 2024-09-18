obj-m += the_rf_file_protection.o
the_rf_file_protection-objs += rf_file_protection.o lib/scth.o

sys_call_table_address = $(shell cat /sys/module/the_usctm/parameters/sys_call_table_address)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

mount:
	insmod the_rf_file_protection.ko syscall_table=$(sys_call_table_address) 

unmount:
	rmmod the_rf_file_protection