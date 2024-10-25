# LinuxReferenceMonitor
Linux Kernel Module (LKM) implementing a reference monitor for file protection.

## Preliminary steps
To use this module, you first need to install [this another Linux Kernel Module](https://github.com/FrancescoQuaglia/Linux-sys_call_table-discoverer) that allows the discovery of the system call table address.

## How to mount
To mount this module you need to:
1. open a shell in main directory of the module
2. execute the command ```sudo bash load.sh <rm_password>```

## How to unmount
To mount this module you need to:
1. open a shell in main directory of the module
2. execute the command ```make unmount```
3. execute the command ```make clean```, to clean all building files.