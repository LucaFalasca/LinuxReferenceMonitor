# LinuxReferenceMonitor
Linux Kernel Module (LKM) implementing a reference monitor for file protection.

## Preliminary steps
To use this module, you first need to download [this another Linux Kernel Module](https://github.com/FrancescoQuaglia/Linux-sys_call_table-discoverer) that allows the discovery of the system call table address and copy it to the project folder.

## How to mount 
To mount this module you need to:
1. open a shell in main directory of the module
2. execute the command ```make``` to build the module
3. execute the command ```make mount_submodule``` to mount the LKM for Syscall Discovery
4. execute the command ```make load_fs``` to mount the file system for logging
5. execute the command ```make mount rm_password=<password>``` for mounting the main kernel module

## How to unmount
To unmount this module you need to:
1. open a shell in main directory of the module
2. execute the command ```make unmount```
2. execute the command ```make unmount_submodule```
3. execute the command ```make clean```, to clean all building files.

## How to unmount file system
Do it only if you don't need anymore the logfile:
1. open a shell in main directory of the module
2. execute the command ```make unload_fs```


## How to use
Go in the ```/user``` directory and execute the command ```make run``` for a client.

## How to test
Go in the ```/user``` directory and execute the command ```make run_test``` for running tests.
