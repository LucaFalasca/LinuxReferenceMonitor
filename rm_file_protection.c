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
        spin_lock(&state_lock);
        if(param == REC_ON || param == ON){
            enable_kprobes();
        }
        else if(param == REC_OFF || param == OFF){
            disable_kprobes();
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

    kpassword = kmalloc(128, GFP_KERNEL);
    if(copy_from_user(kpassword, password, 128))
    {
            printk("%s: [ERROR] failed to copy password from userspace\n", MODNAME);
            kfree(kpassword);
            return -1;
    }
    printk("%s: the user password is %s\n",MODNAME, kpassword);
    sha256(kpassword, strlen(kpassword), kpassword);

    spin_lock(&password_lock);
    if (strcmp(kpassword, rm_password) == 0){
        printk("%s: password correct\n",MODNAME);
    }
    else{
        printk("%s: password incorrect\n",MODNAME);
        return 2;
    }
    spin_unlock(&password_lock);

    if (state == REC_OFF || state == REC_ON){
        kern_path(param, LOOKUP_FOLLOW, &path);
        inode_id = path.dentry->d_inode->i_ino;
        hashset_add_int(inode_id);
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

    kpassword = kmalloc(128, GFP_KERNEL);
    if(copy_from_user(kpassword, password, 128))
    {
            printk("%s: [ERROR] failed to copy password from userspace\n", MODNAME);
            kfree(kpassword);
            return 1;
    }
    printk("%s: the user password is %s\n",MODNAME, kpassword);
    sha256(kpassword, strlen(kpassword), kpassword);

    spin_lock(&password_lock);
    if (strcmp(kpassword, rm_password) == 0){
        printk("%s: password correct\n",MODNAME);
    }
    else{
        printk("%s: password incorrect\n",MODNAME);
        return 2;
    }
    spin_unlock(&password_lock);

    if(state == REC_OFF || state == REC_ON){
        kern_path(param, LOOKUP_FOLLOW, &path);
        inode_id = path.dentry->d_inode->i_ino;
        hashset_remove_int(inode_id);
        printk("%s: path %s is now unprotected\n",MODNAME, param);
    }else{
        printk("%s: the module is not in the right state to unprotect a path\n",MODNAME);
        return 1;
    }

    return 0;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_change_state = (unsigned long) __x64_sys_change_state;       
long sys_protect_path = (unsigned long) __x64_sys_protect_path; 
long sys_unprotect_path = (unsigned long) __x64_sys_unprotect_path;
#else
#endif


static struct kretprobe krp_open;

static int security_file_open_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct file *file;
    int flags;
    unsigned long inode_id;

    file = (struct file *)regs->di;

    flags = file->f_flags;
    if ((flags & O_WRONLY) || (flags & O_RDWR) || (flags & O_TRUNC) || (flags & O_APPEND)){
        inode_id = file->f_path.dentry->d_inode->i_ino;
        if(hashset_contains_int(inode_id)){
            printk("%s: inode id is protected %lu\n",MODNAME,inode_id);
            return 0;
        }
    }
    return 1;
}

static int block_access_post_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    block_access;
    put_deferred_work();
    printk("%s: blocco l'accesso\n",MODNAME);
    return 0;
}


static struct kretprobe krp_rename;

static int security_file_rename_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct dentry *new_dentry;
    struct dentry *old_dentry;
    struct inode *new_dir;
    struct inode *old_dir;
    unsigned long inode_id;


    old_dir = (struct inode *)regs->di;
    old_dentry = (struct dentry *)regs->si;
    new_dir = (struct inode *)regs->dx;
    new_dentry = (struct dentry *)regs->cx;

    if(new_dentry->d_inode != NULL){
        inode_id = new_dentry->d_inode->i_ino;
    
        if(hashset_contains_int(inode_id)){
            printk("%s: you can't rename a file as a protected file",MODNAME);
            return 0;
        }
    }

    if(old_dentry->d_inode != NULL){
        inode_id = old_dentry->d_inode->i_ino;
    
        if(hashset_contains_int(inode_id)){
            printk("%s: you can't rename a protected file",MODNAME);
            return 0;
        }
    }

    inode_id = new_dir->i_ino;

    if(hashset_contains_int(inode_id)){
        printk("%s: you can't rename a file in a protected directory",MODNAME);
        return 0;
    }


    inode_id = old_dir->i_ino;

    if(hashset_contains_int(inode_id)){
        printk("%s: you can't rename a file in a protected directory",MODNAME);
        return 0;
    }

    return 1;
}

static struct kretprobe krp_link;

static int security_inode_link_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct dentry *old_dentry;
    struct inode *dir;
    struct dentry *new_dentry;
    unsigned long dir_inode_id;

    old_dentry = (struct dentry *)regs->di;
    dir = (struct inode *)regs->si;
    new_dentry = (struct dentry *)regs->dx;

    dir_inode_id = dir->i_ino;
    if(hashset_contains_int(dir_inode_id)){
        printk("%s: you can't create a file in a protected directory",MODNAME);
        return 0;
    }
    return 1;
}

static struct kretprobe krp_symlink;
static struct kretprobe krp_mkdir;
static struct kretprobe krp_mknode;
static struct kretprobe krp_create;
static struct kretprobe krp_unlink;
static struct kretprobe krp_rmdir;

static int security_inode_dir_ops_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct inode *dir;
    unsigned long dir_inode_id;
    unsigned long file_inode_id;
    struct dentry *dentry;

    dir = (struct inode *)regs->di;
    dentry = (struct dentry *)regs->si;


    dir_inode_id = dir->i_ino;
    if (dentry->d_inode == NULL)
        return 1;

    file_inode_id = dentry->d_inode->i_ino;

    if(hashset_contains_int(dir_inode_id)){
        printk("%s: you can't operate in a protected directory with node_id %lu",MODNAME, dir_inode_id);
        return 0;
    }
    if(hashset_contains_int(file_inode_id)){
        printk("%s: you can't operate in a protected file with node_id %lu",MODNAME, file_inode_id);
        return 0;
    }
    return 1;
}

int enable_kprobes(){
    enable_kretprobe(&krp_open);
    enable_kretprobe(&krp_rename);
    enable_kretprobe(&krp_link);
    enable_kretprobe(&krp_symlink);
    enable_kretprobe(&krp_unlink);
    enable_kretprobe(&krp_mkdir);
    enable_kretprobe(&krp_rmdir);
    enable_kretprobe(&krp_mknode);
    enable_kretprobe(&krp_create);
    printk("%s: probes enabled\n",MODNAME);
    return 0;
}

int disable_kprobes(){
    disable_kretprobe(&krp_open);
    disable_kretprobe(&krp_rename);
    disable_kretprobe(&krp_link);
    disable_kretprobe(&krp_symlink);
    disable_kretprobe(&krp_unlink);
    disable_kretprobe(&krp_mkdir);
    disable_kretprobe(&krp_rmdir);
    disable_kretprobe(&krp_mknode);
    disable_kretprobe(&krp_create);
    printk("%s: probes disabled\n",MODNAME);
    return 0;
}

typedef struct _packed_work{
        void* buffer;
        __kernel_time64_t ts;
        int tgid;
        int tid;
        int uid;
        int euid;
        char *prog_path;
        struct work_struct the_work;
} packed_work;

int put_deferred_work(void){
    packed_work *the_task;
    struct timespec64 ts;
    struct dentry *dentry;
    char buff[512];
    char *path;

    if(!try_module_get(THIS_MODULE)) return -ENODEV;

    the_task = kzalloc(sizeof(packed_work),GFP_ATOMIC);//non blocking memory allocation

    if (the_task == NULL) {
            printk("%s: tasklet buffer allocation failure\n",MODNAME);
            module_put(THIS_MODULE);
            return -1;
    }
    ktime_get_real_ts64(&ts);

    the_task->buffer = the_task;
    the_task->ts = ts.tv_sec;
    the_task->tgid = current->tgid;
    the_task->tid = current->pid;
    the_task->uid = current_uid().val;
    the_task->euid = current_euid().val;
    dentry = current->mm->exe_file->f_path.dentry;
    path = kmalloc(MAX_FILENAME_LEN, GFP_KERNEL);
    path = dentry_path_raw(dentry, buff, MAX_FILENAME_LEN);
    if(IS_ERR(path)){
        printk("%s: [ERROR] could not get the path of the executable\n",MODNAME);
    }
    printk("%s: the path of the executable is %s\n",MODNAME,path);
    the_task->prog_path = kstrdup(path, GFP_KERNEL);

    printk("%s: the path of the executable is %s\n",MODNAME,the_task->prog_path);

    __INIT_WORK(&(the_task->the_work),(void*)update_access_denied_log,(unsigned long)(&(the_task->the_work)));

    schedule_work(&the_task->the_work);
    printk("%s: deferred work scheduled\n",MODNAME);
    return 0;
}

void update_access_denied_log(unsigned long data){
    packed_work *the_task;
    struct file *sffs_file;
    struct file *malicious_file;
    int ret;
    char output[512];
    int len;
    char prog_cont_hash[65];
    char *prog_cont;
    int file_size;


    printk("%s: I'm in the deferred work\n",MODNAME);

    the_task = container_of((void*)data,packed_work,the_work);

    strcpy(prog_cont_hash, "N/A");
    printk("%s: the path of the executable is %s\n",MODNAME,the_task->prog_path);
    malicious_file = filp_open(the_task->prog_path, O_RDONLY, 0);
    if (IS_ERR(malicious_file)) {
        printk("%s: [ERROR] could not open file with error value %ld\n", MODNAME, PTR_ERR(malicious_file));
    }
    else{
        printk("%s: malicious file opened correctly \n",MODNAME);
        file_size = malicious_file->f_inode->i_size;
        printk("%s: file size %d\n",MODNAME,file_size);
        prog_cont = kmalloc(file_size + 1, GFP_KERNEL);
        if(prog_cont == NULL){
            printk("%s: [ERROR] could not allocate memory for the file content\n",MODNAME);
        }else{
            ret = kernel_read(malicious_file, prog_cont, file_size, 0);
            if(ret < 0){
                printk("%s: [ERROR] could not read from malicious file\n", MODNAME);
            }
            else{
                printk("%s: malicious file read correctly\n",MODNAME);
                printk("%s: ret %d\n",MODNAME,ret);
                printk("%s: the content of the file is %s\n",MODNAME,prog_cont);
                printk("%s: sizeof(progcont) %ld\n",MODNAME,sizeof(prog_cont));
                sha256(prog_cont, ret, prog_cont_hash);
                printk("%s: the hash of the content is %s\n",MODNAME,prog_cont_hash);
            }
        }
        filp_close(malicious_file, NULL);
    }
    
    printk("%s: I'll write the code in the log\n",MODNAME);
    memset(output, 0, 512);
    
    len = snprintf(NULL, 0, "%lld,%d,%d,%d,%d,%s,%s\n\n", the_task->ts, the_task->tgid, the_task->tid, the_task->uid, the_task->euid, the_task->prog_path, prog_cont_hash);
    if(len > 512){
        printk("%s: [ERROR] buffer too small\n",MODNAME);
        return;
    }
    printk("%s: len %d\n",MODNAME,len);
    snprintf(output, len, "%lld,%d,%d,%d,%d,%s,%s\n\n", the_task->ts, the_task->tgid, the_task->tid, the_task->uid, the_task->euid, the_task->prog_path, prog_cont_hash);
    sffs_file = filp_open("/home/luca/LinuxReferenceMonitor/singlefile-FS/mount/access_denied_log.csv", O_WRONLY, 0644);
    if (IS_ERR(sffs_file)) {
        printk("%s: [ERROR] could not open file with error value %ld\n", MODNAME, PTR_ERR(sffs_file));
    }
    else{
        printk("%s: file opened correctly \n",MODNAME);
        ret = kernel_write(sffs_file, output, len - 1, 0);
        if(ret < 0){
            printk("%s: [ERROR] could not write to file\n", MODNAME);
        }
        else{
            printk("%s: file written correctly\n",MODNAME);
        }
        //close the file
        filp_close(sffs_file, NULL);
    }

    kfree(the_task);
    kfree(prog_cont);
    printk("%s: deferred work completed\n",MODNAME);
    module_put(THIS_MODULE);
}

// MODULE INIT -------------------------------------------------------------------------------------------

int init_module(void) {

    int i;
    int ret;
    char *string;
    struct path path;
    unsigned long inode_id;
    struct file *sffs_file;

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

    string = "/home/luca/Documents/prova_folder";
    //hashset_add(string);
    kern_path(string, LOOKUP_FOLLOW, &path);
    inode_id = path.dentry->d_inode->i_ino;
    printk("%s: inode idddd %lu\n",MODNAME,inode_id);
    hashset_add_int(inode_id);

    string = "/home/luca/Documents/prova_folder/a.txt";
    kern_path(string, LOOKUP_FOLLOW, &path);
    inode_id = path.dentry->d_inode->i_ino;
    printk("%s: inode id a.txt file: %lu\n",MODNAME,inode_id);


    printk("%s: string %s is added to the protected paths\n",MODNAME, string);
    string = "Esempio di stringa 2";
    ret = hashset_contains_int(1969749);
    if (ret == 1){
        printk("%s: string %s is in the hashset\n",MODNAME, string);
    }
    else{
        printk("%s: string %s is not in the hashset\n",MODNAME, string);
    }

    krp_open.kp.symbol_name = "security_file_open";
    krp_open.entry_handler = (kretprobe_handler_t)security_file_open_entry_handler;
    krp_open.handler = (kretprobe_handler_t)block_access_post_handler;
    ret = register_kretprobe(&krp_open);

    if (ret < 0) {
        printk("%s: [ERROR] register_kretprobe failed for krp_open\n", MODNAME);
    }
    
    krp_rename.kp.symbol_name = "security_inode_rename";
    krp_rename.entry_handler = (kretprobe_handler_t)security_file_rename_entry_handler;
    krp_rename.handler = (kretprobe_handler_t)block_access_post_handler;
    ret = register_kretprobe(&krp_rename);

    if (ret < 0) {
        printk("%s: [ERROR] register_kretprobe failed for krp_rename\n", MODNAME);
    }

    krp_link.kp.symbol_name = "security_inode_link";
    krp_link.entry_handler = (kretprobe_handler_t)security_inode_link_entry_handler;
    krp_link.handler = (kretprobe_handler_t)block_access_post_handler;
    ret = register_kretprobe(&krp_link);

    if (ret < 0) {
        printk("%s: [ERROR] register_kretprobe failed for krp_link\n", MODNAME);
    }

    krp_symlink.kp.symbol_name = "security_inode_symlink";
    krp_symlink.entry_handler = (kretprobe_handler_t)security_inode_dir_ops_entry_handler;
    krp_symlink.handler = (kretprobe_handler_t)block_access_post_handler;
    ret = register_kretprobe(&krp_symlink);

    if (ret < 0) {
        printk("%s: [ERROR] register_kretprobe failed for krp_symlink\n", MODNAME);
    }

    krp_unlink.kp.symbol_name = "security_inode_unlink";
    krp_unlink.entry_handler = (kretprobe_handler_t)security_inode_dir_ops_entry_handler;
    krp_unlink.handler = (kretprobe_handler_t)block_access_post_handler;
    ret = register_kretprobe(&krp_unlink);

    if (ret < 0) {
        printk("%s: [ERROR] register_kretprobe failed for krp_unlink\n", MODNAME);
    }

    krp_mkdir.kp.symbol_name = "security_inode_mkdir";
    krp_mkdir.entry_handler = (kretprobe_handler_t)security_inode_dir_ops_entry_handler;
    krp_mkdir.handler = (kretprobe_handler_t)block_access_post_handler;
    ret = register_kretprobe(&krp_mkdir);

    if (ret < 0) {
        printk("%s: [ERROR] register_kretprobe failed for krp_mkdir\n", MODNAME);
    }

    krp_rmdir.kp.symbol_name = "security_inode_rmdir";
    krp_rmdir.entry_handler = (kretprobe_handler_t)security_inode_dir_ops_entry_handler;
    krp_rmdir.handler = (kretprobe_handler_t)block_access_post_handler;
    ret = register_kretprobe(&krp_rmdir);

    if (ret < 0) {
        printk("%s: [ERROR] register_kretprobe failed for krp_rmdir\n", MODNAME);
    }

    krp_mknode.kp.symbol_name = "security_inode_mknod";
    krp_mknode.entry_handler = (kretprobe_handler_t)security_inode_dir_ops_entry_handler;
    krp_mknode.handler = (kretprobe_handler_t)block_access_post_handler;
    ret = register_kretprobe(&krp_mknode);

    if (ret < 0) {
        printk("%s: [ERROR] register_kretprobe failed for krp_mknode\n", MODNAME);
    }

    krp_create.kp.symbol_name = "security_inode_create";
    krp_create.entry_handler = (kretprobe_handler_t)security_inode_dir_ops_entry_handler;
    krp_create.handler = (kretprobe_handler_t)block_access_post_handler;
    ret = register_kretprobe(&krp_create);

    if (ret < 0) {
        printk("%s: [ERROR] register_kretprobe failed for krp_create\n", MODNAME);
    }

    /*
    //open the file in write mode
    file = filp_open("/home/luca/Documents/prova_folder", O_WRONLY, 0);
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
    */

    /*
    sffs_file = filp_open("./singlefile-FS/mount/the-file", O_WRONLY, 0644);
    if (IS_ERR(sffs_file)) {
        printk("%s: [ERROR] could not open file with error value %ld\n", MODNAME, PTR_ERR(sffs_file));
    }
    else{
        printk("%s: file opened correctly \n",MODNAME);
        ret = kernel_write(sffs_file, "prova", 5, 0);
        if(ret < 0){
            printk("%s: [ERROR] could not write to file\n", MODNAME);
        }
        else{
            printk("%s: file written correctly\n",MODNAME);
        }
        //close the file
        filp_close(sffs_file, NULL);
    }
    */
    //put_deferred_work();

    return 0;

}

// MODULE CLEANUP -------------------------------------------------------------------------------------------
void cleanup_module(void) {

    int i;
            
    printk("%s: shutting down\n",MODNAME);

    unregister_kretprobe(&krp_open);
    unregister_kretprobe(&krp_rename);
    unregister_kretprobe(&krp_link);
    unregister_kretprobe(&krp_symlink);
    unregister_kretprobe(&krp_unlink);
    unregister_kretprobe(&krp_mkdir);
    unregister_kretprobe(&krp_rmdir);
    unregister_kretprobe(&krp_mknode);
    unregister_kretprobe(&krp_create);

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