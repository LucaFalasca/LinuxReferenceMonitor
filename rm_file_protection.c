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
#include <linux/stringhash.h>

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


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luca Falasca <luca.falasca@students.uniroma2.eu>");
MODULE_DESCRIPTION("RM file protection module");

#define MODNAME "RM_FILE_PROTECTION"

#define MAX_FILENAME_LEN 512

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

// DEFINE HERE THE SYSTEM CALL NAMES
#define sys0 sys0
#define sys1 sys1
#define sys2 sys2

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

module_param(sys0, int, 0664);
module_param(sys1, int, 0664);
module_param(sys2, int, 0664);

SysCallEntry new_sys_call_array[] = {
    {TOSTRING(sys0), 0x0, -1}, 
    {TOSTRING(sys1), 0x0, -1},
    {TOSTRING(sys2), 0x0, -1}
};
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(SysCallEntry))
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};

#define OFF 0
#define ON 1
#define REC_ON 2
#define REC_OFF 3

int state = REC_ON;

module_param(state, int, 0660);
char rm_password[128];
module_param_string(rm_password, rm_password, 128, 0664);

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
__SYSCALL_DEFINEx(2, _protect_path, char *, param, char *, password){
#else
asmlinkage long sys_protect_path(char *param, char *password){
#endif
    // Content of the sys_call
    char *kpassword;

    kpassword = kmalloc(128, GFP_KERNEL);
    if(copy_from_user(kpassword, password, 128))
    {
            printk("%s: [ERROR] failed to copy password from userspace\n", MODNAME);
            kfree(kpassword);
            return -1;
    }
    printk("%s: the user password is %s\n",MODNAME, kpassword);
    sha256(kpassword, strlen(kpassword), kpassword);

    if (strcmp(kpassword, rm_password) == 0){
        printk("%s: password correct\n",MODNAME);
    }
    else{
        printk("%s: password incorrect\n",MODNAME);
    }

    hashset_add(param);
    printk("%s: path %s is now protected\n",MODNAME, param);

    return 0;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _unprotect_path, char *, param, char *, password){
#else
asmlinkage long sys_unprotect_path(char *param, char *password){
#endif
    // Content of the sys_call
    char *kpassword;

    kpassword = kmalloc(128, GFP_KERNEL);
    if(copy_from_user(kpassword, password, 128))
    {
            printk("%s: [ERROR] failed to copy password from userspace\n", MODNAME);
            kfree(kpassword);
            return -1;
    }
    printk("%s: the user password is %s\n",MODNAME, kpassword);
    sha256(kpassword, strlen(kpassword), kpassword);

    if (strcmp(kpassword, rm_password) == 0){
        printk("%s: password correct\n",MODNAME);
    }
    else{
        printk("%s: password incorrect\n",MODNAME);
    }

    hashset_remove(param);
    printk("%s: path %s is now unprotected\n",MODNAME, param);

    return 0;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_change_state = (unsigned long) __x64_sys_change_state;       
long sys_protect_path = (unsigned long) __x64_sys_protect_path; 
long sys_unprotect_path = (unsigned long) __x64_sys_unprotect_path;
#else
#endif

static int security_file_open_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct path *path;
    struct file *file;
    struct dentry *dentry;
    char *buff;
    char *pathname;
    int flags;

    file = (struct file *)regs->di;

    flags = file->f_flags;
    if ((flags & O_WRONLY) || (flags & O_RDWR) || (flags & O_TRUNC) || (flags & O_APPEND)){
        path = &file->f_path;
        dentry = path->dentry;

        buff = (char *)kmalloc(GFP_KERNEL, MAX_FILENAME_LEN);
        if (!buff) {
                printk("%s: [ERROR] could not allocate memory for buffer\n", MODNAME);
                return 1;
        }
        pathname = dentry_path_raw(dentry, buff, MAX_FILENAME_LEN);
        if (IS_ERR(pathname)) {
                printk("%s: [ERROR] could not get path from dentry\n", MODNAME);
                kfree(buff);
                return 1;
        }
        if (hashset_contains(pathname) == 1){
            printk("%s: file %s is protected\n", MODNAME, pathname);
            return 0;
        }
    }
    return 1;
}

static int security_file_open_post_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    regs->ax = (-EACCES);
    printk("%s: blocco l'accesso\n",MODNAME);
    return 0;
}



static struct kretprobe krp_open;

// MODULE INIT -------------------------------------------------------------------------------------------

int init_module(void) {

    int i;
    int ret;
    char *string;
    struct file *file;

    if (strlen(rm_password) == 0){
        printk("%s: password not inserted\n",MODNAME);
        return -1;
    }

    sha256(rm_password, strlen(rm_password), rm_password);
    printk("%s: the hashed password is %s\n", MODNAME, rm_password);

	if (syscall_table == 0x0){
        printk("%s: cannot manage sys_call_table address set to 0x0\n",MODNAME);
        return -1;
	}

    printk("%s: the module received sys_call_table address %px\n",MODNAME,(void*)syscall_table);
    printk("%s: initializing - hacked entries %d\n",MODNAME,HACKED_ENTRIES);

	new_sys_call_array[0].value = (unsigned long)sys_change_state;
    new_sys_call_array[1].value = (unsigned long)sys_protect_path;
    new_sys_call_array[2].value = (unsigned long)sys_unprotect_path;

    

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

	protect_memory();

    printk("%s: all new system-calls correctly installed on sys-call table\n",MODNAME);

    hashset_init();

    string = "/home/luca/Documents/prova_protezione.txt";
    hashset_add(string);
    printk("%s: string %s is added to the protected paths\n",MODNAME, string);
    string = "Esempio di stringa 2";
    ret = hashset_contains(string);
    if (ret == 1){
        printk("%s: string %s is in the hashset\n",MODNAME, string);
    }
    else{
        printk("%s: string %s is not in the hashset\n",MODNAME, string);
    }

    krp_open.kp.symbol_name = "security_file_open";
    krp_open.entry_handler = (kretprobe_handler_t)security_file_open_entry_handler;
    krp_open.handler = (kretprobe_handler_t)security_file_open_post_handler;
    ret = register_kretprobe(&krp_open);

    //open the file in write mode
    file = filp_open("/home/luca/Documents/prova_protezione.txt", O_WRONLY, 0);
    if (IS_ERR(file)) {
        printk("%s: [ERROR] could not open file\n", MODNAME);
    }
    else{
        printk("%s: file opened correctly\n",MODNAME);
         //close the file
        filp_close(file, NULL);
    }
    //apro il file in tutti gli altri modi di strcittura
    file = filp_open("/home/luca/Documents/prova_protezione.txt", O_RDWR, 0);
    if (IS_ERR(file)) {
        printk("%s: [ERROR] could not open file\n", MODNAME);
    }
    else{
        printk("%s: file opened correctly\n",MODNAME);
        filp_close(file, NULL);
    }
    file = filp_open("/home/luca/Documents/prova_protezione.txt", O_TRUNC, 0);
    if (IS_ERR(file)) {
        printk("%s: [ERROR] could not open file\n", MODNAME);
    }
    else{
        printk("%s: file opened correctly\n",MODNAME);
        //close the file
        filp_close(file, NULL);
    }
    
    file = filp_open("/home/luca/Documents/prova_protezione.txt", O_APPEND, 0);
    if (IS_ERR(file)) {
        printk("%s: [ERROR] could not open file\n", MODNAME);
    }
    else{
        printk("%s: file opened correctly\n",MODNAME);
        //close the file
        filp_close(file, NULL);
    }
    file = filp_open("/home/luca/Documents/prova_protezione.txt", O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk("%s: [ERROR] could not open file\n", MODNAME);
    }
    else{
        printk("%s: file opened correctly\n",MODNAME);
        //close the file
        filp_close(file, NULL);
    }
    

    return 0;

}

// MODULE CLEANUP -------------------------------------------------------------------------------------------
void cleanup_module(void) {

    int i;
            
    printk("%s: shutting down\n",MODNAME);

    unregister_kretprobe(&krp_open);
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
