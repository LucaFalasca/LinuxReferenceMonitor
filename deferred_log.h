#include "rm_file_protection.h"

#define LOG_PATH "/var/logfs/access_denied_log.csv"

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
    the_task->prog_path = kstrdup(path, GFP_KERNEL);

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

    the_task = container_of((void*)data,packed_work,the_work);

    strcpy(prog_cont_hash, "N/A");
    printk("%s: the path of the executable is %s\n",MODNAME,the_task->prog_path);
    malicious_file = filp_open(the_task->prog_path, O_RDONLY, 0);
    if (IS_ERR(malicious_file)) {
        printk("%s: [ERROR] could not open file with error value %ld\n", MODNAME, PTR_ERR(malicious_file));
    }
    else{
        file_size = malicious_file->f_inode->i_size;
        prog_cont = kmalloc(file_size + 1, GFP_KERNEL);
        if(prog_cont == NULL){
            printk("%s: [ERROR] could not allocate memory for the file content\n",MODNAME);
        }else{
            ret = kernel_read(malicious_file, prog_cont, file_size, 0);
            if(ret < 0){
                printk("%s: could not read from malicious file\n", MODNAME);
            }
            else{
                sha256(prog_cont, ret, prog_cont_hash);
            }
        }
        filp_close(malicious_file, NULL);
    }
    printk("%s: Writing the info in the log\n",MODNAME);
    memset(output, 0, 512);
    
    len = snprintf(NULL, 0, "%lld,%d,%d,%d,%d,%s,%s\n\n", the_task->ts, the_task->tgid, the_task->tid, the_task->uid, the_task->euid, the_task->prog_path, prog_cont_hash);
    if(len > 512){
        printk("%s: [ERROR] buffer too small\n",MODNAME);
        kfree(the_task);
        kfree(prog_cont);
        module_put(THIS_MODULE);
        return;
    }
    snprintf(output, len, "%lld,%d,%d,%d,%d,%s,%s\n\n", the_task->ts, the_task->tgid, the_task->tid, the_task->uid, the_task->euid, the_task->prog_path, prog_cont_hash);
    
    sffs_file = filp_open(LOG_PATH, O_WRONLY, 0644);
    if (IS_ERR(sffs_file)) {
        printk("%s: [ERROR] could not open file with error value %ld, the file system may not be mounted, or it may be mounted in the wrong folder\n", MODNAME, PTR_ERR(sffs_file));
        kfree(the_task);
        kfree(prog_cont);
        module_put(THIS_MODULE);
        return;
    }
    else{
        printk("%s: file opened correctly \n",MODNAME);
        ret = kernel_write(sffs_file, output, len - 1, 0);
        if(ret < 0){
            printk("%s: [ERROR] could not write to file\n", MODNAME);
            kfree(the_task);
            kfree(prog_cont);
            module_put(THIS_MODULE);
        }
        else{
            printk("%s: file written correctly\n",MODNAME);
        }
        filp_close(sffs_file, NULL);
    }

    kfree(the_task);
    kfree(prog_cont);
    printk("%s: deferred work completed\n",MODNAME);
    module_put(THIS_MODULE);
}