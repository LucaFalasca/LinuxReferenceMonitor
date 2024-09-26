#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <asm/io.h>
#include <linux/syscalls.h>
#include "lib/include/scth.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luca Falasca <luca.falasca@students.uniroma2.eu>");
MODULE_DESCRIPTION("RM file protection module");

#define MODNAME "RM_FILE_PROTECTION"


#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

// DEFINE HERE THE SYSTEM CALL NAMES
#define sys0 sys0
#define sys1 sys1

unsigned long syscall_table = 0x0;
module_param(syscall_table, ulong, 0660);
unsigned long the_ni_syscall;

typedef struct {
    const char *name;
    unsigned long value;
    int entry;
} SysCallEntry;

int sys0 = -1;
int sys1 = -1;

module_param(sys0, int, 0660);
module_param(sys1, int, 0660);

SysCallEntry new_sys_call_array[] = {
    {TOSTRING(sys0), 0x0, -1}, 
    {TOSTRING(sys1), 0x0, -1}
};
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(SysCallEntry))
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};

#define OFF 0
#define ON 1
#define REC_ON 2
#define REC_OFF 3

int state = REC_ON;

module_param(state, int, 0660);

// SYS CALL DEFINE -------------------------------------------------------------------------------------------
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _change_state, unsigned long, param){
#else
asmlinkage long sys_change_state(unsigned long param){
#endif
    // Content of the sys_call
    kuid_t euid;
    printk("%s: sys_change_state called with param %lx\n",MODNAME,param);
    euid = current_euid();
    printk("%s: euid %d\n",MODNAME,euid.val);
    if(!uid_eq(euid, GLOBAL_ROOT_UID)){
        printk("%s: only root can change the state\n",MODNAME);
        return -1;
    }
    else if(param < OFF || param > REC_OFF){
        printk("%s: invalid state\n",MODNAME);
        return -1;
    }
    else{
        state = param;
        printk("%s: state changed to %d\n",MODNAME,state);
    }
    
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _test1, unsigned long, param){
#else
asmlinkage long sys_test1(unsigned long param){
#endif
    // Content of the sys_call
    printk("%s: sys_test1 called with param %lx\n",MODNAME,param);
    return 0;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_change_state = (unsigned long) __x64_sys_change_state;       
long sys_test1 = (unsigned long) __x64_sys_test1; 
#else
#endif

// MODULE INIT -------------------------------------------------------------------------------------------

int init_module(void) {

    int i;
    int ret;

	if (syscall_table == 0x0){
        printk("%s: cannot manage sys_call_table address set to 0x0\n",MODNAME);
        return -1;
	}

    printk("%s: the module received sys_call_table address %px\n",MODNAME,(void*)syscall_table);
    printk("%s: initializing - hacked entries %d\n",MODNAME,HACKED_ENTRIES);


	new_sys_call_array[0].value = (unsigned long)sys_change_state;
    new_sys_call_array[1].value = (unsigned long)sys_test1;

    

    ret = get_entries(restore,HACKED_ENTRIES,(unsigned long*)syscall_table,&the_ni_syscall);

    if (ret != HACKED_ENTRIES){
        printk("%s: could not hack %d entries (just %d)\n",MODNAME,HACKED_ENTRIES,ret); 
        return -1;      
    }

	unprotect_memory();

    for(i = 0; i < HACKED_ENTRIES; i++){
        ((unsigned long *)syscall_table)[restore[i]] = (unsigned long)new_sys_call_array[i].value;
        printk("%s: syscall %s with entry %d",MODNAME, new_sys_call_array[i].name, restore[i]);
        new_sys_call_array[i].entry = restore[i];
    }

    sys0 = new_sys_call_array[0].entry;
    sys1 = new_sys_call_array[1].entry;

	protect_memory();

    printk("%s: all new system-calls correctly installed on sys-call table\n",MODNAME);

    return 0;

}

// MODULE CLEANUP -------------------------------------------------------------------------------------------
void cleanup_module(void) {

    int i;
            
    printk("%s: shutting down\n",MODNAME);

	unprotect_memory();
    for(i = 0; i < HACKED_ENTRIES; i++){
            ((unsigned long *)syscall_table)[restore[i]] = the_ni_syscall;
    }
	protect_memory();
    printk("%s: sys-call table restored to its original content\n",MODNAME);
}
