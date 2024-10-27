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
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/hashtable.h>
#include "path_hash_set.h"
#include <linux/ktime.h>
#include <linux/namei.h>
#include "rm_file_protection.h"
#include "hookes.h"
#include "deferred_log.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luca Falasca <luca.falasca@students.uniroma2.eu>");
MODULE_DESCRIPTION("Reference Monitor for file protection module");

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

// DEFINE HERE THE SYSTEM CALL NAMES
#define sys0 sys0
#define sys1 sys1
#define sys2 sys2
#define sys3 sys3

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
int sys2 = -1;
int sys3 = -1;

module_param(sys0, int, 0664);
module_param(sys1, int, 0664);
module_param(sys2, int, 0664);
module_param(sys3, int, 0664);

SysCallEntry new_sys_call_array[] = {
    {TOSTRING(sys0), 0x0, -1}, 
    {TOSTRING(sys1), 0x0, -1},
    {TOSTRING(sys2), 0x0, -1},
    {TOSTRING(sys3), 0x0, -1}
};
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(SysCallEntry))
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};

#define OFF 0
#define ON 1
#define REC_ON 2
#define REC_OFF 3

#define block_access regs->ax = (-EACCES)

int state = REC_ON;
spinlock_t state_lock;

module_param(state, int, 0660);
char rm_password[128];
spinlock_t password_lock;
module_param_string(rm_password, rm_password, 128, 0664);

// SYS CALL DEFINE -------------------------------------------------------------------------------------------
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _change_state, unsigned long, param){
#else
asmlinkage long sys_change_state(unsigned long param){
#endif
    // Content of the sys_call
    kuid_t euid;
    euid = current_euid();
    if(!uid_eq(euid, GLOBAL_ROOT_UID)){
        printk("%s: only root can change the state\n",MODNAME);
        return -1;
    }
    else if(param < OFF || param > REC_OFF){
        printk("%s: invalid state\n",MODNAME);
        return -1;
    }
    else{
        spin_lock(&state_lock);
        if((param == REC_ON || param == ON) && (state == REC_OFF || state == OFF)){
            enable_hooks();
        }
        else if((param == REC_OFF || param == OFF) && (state == REC_ON || state == ON)){
            disable_hooks();
        }
        state = param;
        spin_unlock(&state_lock);
        printk("%s: state changed to %d\n",MODNAME,state);
    }
    
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _protect_path, char *, param, char *, password){
#else
asmlinkage long sys_protect_path(char *param, char *password){
#endif
    // Content of the sys_call
    char *kpassword;
    struct path path;
    unsigned long inode_id;
    int ret;

    kpassword = kmalloc(128, GFP_KERNEL);
    if(copy_from_user(kpassword, password, 128))
    {
            printk("%s: [ERROR] failed to copy password from userspace\n", MODNAME);
            kfree(kpassword);
            return -1;
    }
    sha256(kpassword, strlen(kpassword), kpassword);

    spin_lock(&password_lock);
    if (strcmp(kpassword, rm_password) == 0){
        printk("%s: password correct\n",MODNAME);
    }
    else{
        printk("%s: password incorrect\n",MODNAME);
        kfree(kpassword);
        return 2;
    }
    spin_unlock(&password_lock);
    kfree(kpassword);

    if (state == REC_OFF || state == REC_ON){
        printk("%s: 1\n",MODNAME);
        ret = kern_path(param, LOOKUP_FOLLOW, &path);
        printk("%s: 2\n",MODNAME);
        if(ret < 0){
            printk("%s: error trying to access the path\n",MODNAME);
            return 1;
        }
        if(path.dentry->d_inode == NULL){
            printk("%s: path %s does not exist\n",MODNAME, param);
            return 1;
        }
        inode_id = path.dentry->d_inode->i_ino;
        printk("%s: 3\n",MODNAME);
        printk("%s: inode id %lu\n",MODNAME,inode_id);
        if(hashset_contains_int(inode_id)){
            printk("%s: path %s is already protected\n",MODNAME, param);
            return 1;
        }
        printk("%s: 4\n",MODNAME);
        hashset_add_int(inode_id);
        printk("%s: 5\n",MODNAME);
        printk("%s: path %s is now protected\n",MODNAME, param);
    }
    else{
        printk("%s: the module is not in the right state to protect a path\n",MODNAME);
        return 1;
    }

    return 0;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _unprotect_path, char *, param, char *, password){
#else
asmlinkage long sys_unprotect_path(char *param, char *password){
#endif
    // Content of the sys_call
    char *kpassword;
    struct path path;
    unsigned long inode_id;
    int ret;

    kpassword = kmalloc(128, GFP_KERNEL);
    if(copy_from_user(kpassword, password, 128))
    {
            printk("%s: [ERROR] failed to copy password from userspace\n", MODNAME);
            kfree(kpassword);
            return 1;
    }
    sha256(kpassword, strlen(kpassword), kpassword);

    spin_lock(&password_lock);
    if (strcmp(kpassword, rm_password) == 0){
        printk("%s: password correct\n",MODNAME);
    }
    else{
        printk("%s: password incorrect\n",MODNAME);
        kfree(kpassword);
        return 2;
    }
    spin_unlock(&password_lock);
    kfree(kpassword);

    if(state == REC_OFF || state == REC_ON){
        ret = kern_path(param, LOOKUP_FOLLOW, &path);
        if(ret < 0){
            printk("%s: error trying to access the path\n",MODNAME);
            return 1;
        }
        if(path.dentry->d_inode == NULL){
            printk("%s: path %s does not exist\n",MODNAME, param);
            return 1;
        }
        inode_id = path.dentry->d_inode->i_ino;
        if(!hashset_contains_int(inode_id)){
            printk("%s: path %s is not protected\n",MODNAME, param);
            return 1;
        }
        hashset_remove_int(inode_id);
        printk("%s: path %s is now unprotected\n",MODNAME, param);
    }else{
        printk("%s: the module is not in the right state to unprotect a path\n",MODNAME);
        return 1;
    }

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _change_password, char *, old_password, char *, new_password){
#else
asmlinkage long sys_change_password(char *old_password, char *new_password){
#endif
    char *kold_password, *knew_password;

    kold_password = kmalloc(128, GFP_KERNEL);
    knew_password = kmalloc(128, GFP_KERNEL);
    if(copy_from_user(kold_password, old_password, 128))
    {
            printk("%s: [ERROR] failed to copy password from userspace\n", MODNAME);
            kfree(kold_password);
            return 1;
    }
    if(copy_from_user(knew_password, new_password, 128))
    {
            printk("%s: [ERROR] failed to copy password from userspace\n", MODNAME);
            kfree(knew_password);
            return 1;
    }
    sha256(kold_password, strlen(kold_password), kold_password);

    spin_lock(&password_lock);
    if (strcmp(kold_password, rm_password) == 0){
        printk("%s: password correct\n",MODNAME);
    }
    else{
        printk("%s: password incorrect\n",MODNAME);
        return 2;
    }
    if (strlen(knew_password) == 0){
        printk("%s: password not inserted\n",MODNAME);
        return -1;
    }

    sha256(knew_password, strlen(knew_password), rm_password);
    spin_unlock(&password_lock);
    printk("%s: password changed\n",MODNAME);
    return 0;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_change_state = (unsigned long) __x64_sys_change_state;       
long sys_protect_path = (unsigned long) __x64_sys_protect_path; 
long sys_unprotect_path = (unsigned long) __x64_sys_unprotect_path;
long sys_change_password = (unsigned long) __x64_sys_change_password;
#else
#endif

int sha256(const char *data, long data_size, char *output) {
    struct crypto_shash *tfm;
    struct shash_desc *shash;
    int ret, i;
    char hash[32];

    // Allocate a transformation object
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        return -1;
    }
    // Allocate the hash descriptor
    shash = kmalloc(sizeof(*shash) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!shash) {
        crypto_free_shash(tfm);
        return -1;
    }
    shash->tfm = tfm;
    // Initialize the hash computation
    ret = crypto_shash_init(shash);
    if (ret) {
        kfree(shash);
        crypto_free_shash(tfm);
        return ret;
    }

    // Update with data
    ret = crypto_shash_update(shash, data, data_size);
    if (ret) {
        kfree(shash);
        crypto_free_shash(tfm);
        return ret;
    }
    // Finalize the hash computation
    ret = crypto_shash_final(shash, hash);
    //Convert to hex
    for (i = 0; i < 32; i++) {
        sprintf(output + i * 2, "%02x", (unsigned char)hash[i]);
    }
    output[65] = '\0';
    // Clean up
    kfree(shash);
    crypto_free_shash(tfm);
    return ret;
}

// MODULE INIT -------------------------------------------------------------------------------------------

int init_module(void) {

    int i;
    int ret;

    if (strlen(rm_password) == 0){
        printk("%s: password not inserted\n",MODNAME);
        return -1;
    }

    sha256(rm_password, strlen(rm_password), rm_password);
    printk("%s: password stored successfully\n",MODNAME);

	if (syscall_table == 0x0){
        printk("%s: cannot manage sys_call_table address set to 0x0\n",MODNAME);
        return -1;
	}

    printk("%s: the module received sys_call_table address %px\n",MODNAME,(void*)syscall_table);
    printk("%s: initializing - hacked entries %d\n",MODNAME,HACKED_ENTRIES);

	new_sys_call_array[0].value = (unsigned long)sys_change_state;
    new_sys_call_array[1].value = (unsigned long)sys_protect_path;
    new_sys_call_array[2].value = (unsigned long)sys_unprotect_path;
    new_sys_call_array[3].value = (unsigned long)sys_change_password;


    

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
    sys2 = new_sys_call_array[2].entry;
    sys3 = new_sys_call_array[3].entry;

	protect_memory();

    printk("%s: all new system-calls correctly installed on sys-call table\n",MODNAME);

    hashset_init();
    register_hooks();
    
    printk("%s: the module is now ready\n",MODNAME);
    return 0;
}



// MODULE CLEANUP -------------------------------------------------------------------------------------------
void cleanup_module(void) {

    int i;
            
    printk("%s: shutting down\n",MODNAME);

    unregister_hooks();

    printk("%s: probes unregistered\n",MODNAME);

    hashset_cleanup();
    printk("%s: hashset cleaned\n",MODNAME);

	unprotect_memory();
    for(i = 0; i < HACKED_ENTRIES; i++){
            ((unsigned long *)syscall_table)[restore[i]] = the_ni_syscall;
    }
	protect_memory();
    printk("%s: sys-call table restored to its original content\n",MODNAME);
}

