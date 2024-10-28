# LinuxReferenceMonitor
Linux Kernel Module (LKM) implementing a reference monitor for file protection.

## Preliminary steps
This module use a [submodule](https://github.com/FrancescoQuaglia/Linux-sys_call_table-discoverer)submodule that allows the discovery of the system call table address and copy it to the project folder.
when you clone the project, to make sure you also include the submodule you can use the command:
```git clone --recurse-submodules https://github.com/LucaFalasca/LinuxReferenceMonitor.git```

or if you have already cloned the repository you can run this command in the main directory of the project
```git submodule update --init --recursive```

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
