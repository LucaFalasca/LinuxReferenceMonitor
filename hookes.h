#include "rm_file_protection.h"

#define block_access regs->ax = (-EACCES)

static int security_file_open_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
static int block_access_post_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
static int security_file_rename_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
static int security_inode_link_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
static int security_inode_dir_ops_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
int enable_hooks(void);
int disable_hooks(void);
int register_hooks(void);
int unregister_hooks(void);


static struct kretprobe krp_open = {
    .kp.symbol_name = "security_file_open",
    .entry_handler = (kretprobe_handler_t)security_file_open_entry_handler,
    .handler = (kretprobe_handler_t)block_access_post_handler
};
static struct kretprobe krp_rename ={
    .kp.symbol_name = "security_inode_rename",
    .entry_handler = (kretprobe_handler_t)security_file_rename_entry_handler,
    .handler = (kretprobe_handler_t)block_access_post_handler
};
static struct kretprobe krp_link = {
    .kp.symbol_name = "security_inode_link",
    .entry_handler = (kretprobe_handler_t)security_inode_link_entry_handler,
    .handler = (kretprobe_handler_t)block_access_post_handler
};
static struct kretprobe krp_symlink = {
    .kp.symbol_name = "security_inode_symlink",
    .entry_handler = (kretprobe_handler_t)security_inode_dir_ops_entry_handler,
    .handler = (kretprobe_handler_t)block_access_post_handler
};
static struct kretprobe krp_mkdir = {
    .kp.symbol_name = "security_inode_mkdir",
    .entry_handler = (kretprobe_handler_t)security_inode_dir_ops_entry_handler,
    .handler = (kretprobe_handler_t)block_access_post_handler
};
static struct kretprobe krp_mknode = {
    .kp.symbol_name = "security_inode_mknod",
    .entry_handler = (kretprobe_handler_t)security_inode_dir_ops_entry_handler,
    .handler = (kretprobe_handler_t)block_access_post_handler
};
static struct kretprobe krp_create = {
    .kp.symbol_name = "security_inode_create",
    .entry_handler = (kretprobe_handler_t)security_inode_dir_ops_entry_handler,
    .handler = (kretprobe_handler_t)block_access_post_handler
};
static struct kretprobe krp_unlink = {
    .kp.symbol_name = "security_inode_unlink",
    .entry_handler = (kretprobe_handler_t)security_inode_dir_ops_entry_handler,
    .handler = (kretprobe_handler_t)block_access_post_handler
};
static struct kretprobe krp_rmdir = {
    .kp.symbol_name = "security_inode_rmdir",
    .entry_handler = (kretprobe_handler_t)security_inode_dir_ops_entry_handler,
    .handler = (kretprobe_handler_t)block_access_post_handler
};

static struct kretprobe *kprobes_array[] = {
    &krp_open,
    &krp_rename,
    &krp_link,
    &krp_symlink,
    &krp_unlink,
    &krp_mkdir,
    &krp_rmdir,
    &krp_mknode,
    &krp_create
};

int enable_hooks(){
    int i;
    int ret;
    for(i = 0; i < 9; i++){
        ret = enable_kretprobe(kprobes_array[i]);
        if (ret < 0) {
            printk("%s: [ERROR] enable_kretprobe failed for kprobes_array[%d]\n", MODNAME, i);
        }
    }
    printk("%s: probes enabled\n",MODNAME);
    return 0;
}

int disable_hooks(){
    int i;
    int ret;
    for(i = 0; i < 9; i++){
        ret = disable_kretprobe(kprobes_array[i]);
        if (ret < 0) {
            printk("%s: [ERROR] disable_kretprobe failed for kprobes_array[%d]\n", MODNAME, i);
        }
    }
    printk("%s: probes disabled\n",MODNAME);
    return 0;
}

int register_hooks(){
    int i;
    int ret;
    for(i = 0; i < 9; i++){
        ret = register_kretprobe(kprobes_array[i]);
        if (ret < 0) {
            printk("%s: [ERROR] register_kretprobe failed for kprobes_array[%d]\n", MODNAME, i);
        }
    }
    printk("%s: probes registered\n",MODNAME);
    return 0;
}

int unregister_hooks(){
    int i;
    for(i = 0; i < 9; i++){
        unregister_kretprobe(kprobes_array[i]);
    }
    printk("%s: probes unregistered\n",MODNAME);
    return 0;
}


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
    put_deferred_work();
    block_access;
    printk("%s: blocco l'accesso\n",MODNAME);
    return 0;
}

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

static int security_inode_link_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct dentry *old_dentry;
    struct inode *dir;
    struct dentry *new_dentry;
    unsigned long dir_inode_id;
    unsigned long file_inode_id;

    old_dentry = (struct dentry *)regs->di;
    dir = (struct inode *)regs->si;
    new_dentry = (struct dentry *)regs->dx;

    dir_inode_id = dir->i_ino;
    if(hashset_contains_int(dir_inode_id)){
        printk("%s: you can't create a file in a protected directory",MODNAME);
        return 0;
    }
    file_inode_id = new_dentry->d_inode->i_ino;
    if(hashset_contains_int(file_inode_id)){
        printk("%s: you can't create a protected file",MODNAME);
        return 0;
    }
    file_inode_id = old_dentry->d_inode->i_ino;
    if(hashset_contains_int(file_inode_id)){
        printk("%s: you can't create a link to a protected file",MODNAME);
        return 0;
    }
    return 1;
}


static int security_inode_dir_ops_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct inode *dir;
    unsigned long dir_inode_id;
    unsigned long file_inode_id;
    struct dentry *dentry;

    dir = (struct inode *)regs->di;
    dentry = (struct dentry *)regs->si;


    dir_inode_id = dir->i_ino;

    if(hashset_contains_int(dir_inode_id)){
        printk("%s: you can't operate in a protected directory with node_id %lu",MODNAME, dir_inode_id);
        return 0;
    }

    if (dentry->d_inode == NULL)
        return 1;

    file_inode_id = dentry->d_inode->i_ino;

    if(hashset_contains_int(file_inode_id)){
        printk("%s: you can't operate in a protected file with node_id %lu",MODNAME, file_inode_id);
        return 0;
    }
    return 1;
}
