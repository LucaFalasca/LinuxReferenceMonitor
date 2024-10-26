obj-m += the_rm_file_protection.o
the_rm_file_protection-objs += rm_file_protection.o lib/scth.o

sys_call_table_address = $(shell sudo cat /sys/module/the_usctm/parameters/sys_call_table_address)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/Linux-sys_call_table-discoverer modules 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/Linux-sys_call_table-discoverer clean

mount_submodule:
	sudo insmod Linux-sys_call_table-discoverer/the_usctm.ko

unmount_submodule:
	sudo rmmod Linux-sys_call_table-discoverer/the_usctm.ko

mount:
	sudo insmod the_rm_file_protection.ko syscall_table=$(sys_call_table_address) rm_password=$(rm_password)

unmount:
	sudo rmmod the_rm_file_protection

load_fs:
	sudo bash load_fs.sh

unload_fs:
	sudo bash unload_fs.sh
