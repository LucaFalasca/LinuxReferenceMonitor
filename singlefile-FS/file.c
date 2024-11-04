#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/timekeeping.h>
#include <linux/time.h>
#include <linux/buffer_head.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include "singlefilefs.h"
#include <linux/uio.h>
#include <linux/mutex.h>



ssize_t onefilefs_read(struct file * filp, char __user * buf, size_t len, loff_t * off) {

    struct buffer_head *bh = NULL;
    struct inode * the_inode = filp->f_inode;
    uint64_t file_size;
    int ret;
    loff_t offset;
    int block_to_read;//index of the block to be read from device

    printk("%s: read operation called with len %ld - and offset %lld",MOD_NAME, len, *off);

    mutex_lock(&mutex);
    file_size = the_inode->i_size;
    mutex_unlock(&mutex);

    //check that *off is within boundaries
    if (*off >= file_size)
        return 0;
    else if (*off + len > file_size)
        len = file_size - *off;

    //determine the block level offset for the operation
    offset = *off % DEFAULT_BLOCK_SIZE; 
    //just read stuff in a single block - residuals will be managed at the applicatin level
    if (offset + len > DEFAULT_BLOCK_SIZE)
        len = DEFAULT_BLOCK_SIZE - offset;

    //compute the actual index of the the block to be read from device
    block_to_read = *off / DEFAULT_BLOCK_SIZE + 2; //the value 2 accounts for superblock and file-inode on device
    
    printk("%s: read operation must access block %d of the device",MOD_NAME, block_to_read);

    bh = (struct buffer_head *)sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_read);
    if(!bh){
	return -EIO;
    }
    ret = copy_to_user(buf,bh->b_data + offset, len);
    *off += (len - ret);
    brelse(bh);

    return len - ret;

}


struct dentry *onefilefs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags) {

    struct onefilefs_inode *FS_specific_inode;
    struct super_block *sb = parent_inode->i_sb;
    struct buffer_head *bh = NULL;
    struct inode *the_inode = NULL;

    printk("%s: running the lookup inode-function for name %s",MOD_NAME,child_dentry->d_name.name);

    if(!strcmp(child_dentry->d_name.name, UNIQUE_FILE_NAME)){

	
	//get a locked inode from the cache 
        the_inode = iget_locked(sb, 1);
        if (!the_inode)
       		 return ERR_PTR(-ENOMEM);

	//already cached inode - simply return successfully
	if(!(the_inode->i_state & I_NEW)){
		return child_dentry;
	}


	//this work is done if the inode was not already cached
    #if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 12, 0)
    inode_init_owner(the_inode, NULL, S_IFDIR);
    #elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
    inode_init_owner(&init_user_ns, the_inode, NULL, S_IFDIR);
    #elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
    inode_init_owner(&nop_mnt_idmap, the_inode, NULL, S_IFDIR);
    #endif
	//inode_init_owner(the_inode, NULL, S_IFREG );
	the_inode->i_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IXUSR | S_IXGRP | S_IXOTH;
        the_inode->i_fop = &onefilefs_file_operations;
	the_inode->i_op = &onefilefs_inode_ops;

	//just one link for this file
	set_nlink(the_inode,1);

	//now we retrieve the file size via the FS specific inode, putting it into the generic inode
    	bh = (struct buffer_head *)sb_bread(sb, SINGLEFILEFS_INODES_BLOCK_NUMBER );
    	if(!bh){
		iput(the_inode);
		return ERR_PTR(-EIO);
    	}
	FS_specific_inode = (struct onefilefs_inode*)bh->b_data;
	the_inode->i_size = FS_specific_inode->file_size;
        brelse(bh);

        d_add(child_dentry, the_inode);
	dget(child_dentry);

	//unlock the inode to make it usable 
    	unlock_new_inode(the_inode);

	return child_dentry;
    }

    return NULL;

}


ssize_t onefilefs_append(struct kiocb *iocb, struct iov_iter *from) {
    struct file *filp = iocb->ki_filp;
    struct inode *the_inode = filp->f_inode;
    struct buffer_head *bh;
    loff_t *off = &iocb->ki_pos;
    uint64_t file_size;
    int ret, len, offset, block_to_write;
    size_t write_len = iov_iter_count(from);
    struct onefilefs_inode *FS_specific_inode;

    //printk("%s: write operation called with len %ld - and offset %lld (the current file size is %lld)", MOD_NAME, write_len, *off, file_size);
    
    bh = (struct buffer_head *)sb_bread(filp->f_path.dentry->d_inode->i_sb, SINGLEFILEFS_INODES_BLOCK_NUMBER );
    if(!bh){
		return -EIO;
    }
	FS_specific_inode = (struct onefilefs_inode*)bh->b_data;

    mutex_lock(&mutex);
    file_size = the_inode->i_size;
    // Aggiorna l'offset all'inizio della scrittura in append (fine del file)
    *off = FS_specific_inode->file_size;

    // Gestisci la lunghezza della scrittura in base allo spazio disponibile
    len = min_t(size_t, DEFAULT_BLOCK_SIZE - (*off % DEFAULT_BLOCK_SIZE), write_len);

    

    // Determina il blocco in cui scrivere i dati
    offset = *off % DEFAULT_BLOCK_SIZE;
    block_to_write = *off / DEFAULT_BLOCK_SIZE + 2; // 2 per superblocco e inode
    
    printk("%s: write operation must access block %d of the device", MOD_NAME, block_to_write);

    // Leggi il blocco in cui scrivere
    bh = (struct buffer_head *)sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_write);
    if (!bh) {
        mutex_unlock(&mutex);
        return -EIO;
    }



    // Copia i dati forniti dall'utente nel buffer
    ret = copy_from_iter(bh->b_data + offset, len, from);
    if (ret != len) {
        brelse(bh);
        mutex_unlock(&mutex);
        return -EFAULT;
    }

    // Marca il buffer come sporco per forzare la scrittura su disco
    mark_buffer_dirty(bh);
    brelse(bh);

    // Aggiorna l'offset e la dimensione del file
    *off += len;
    the_inode->i_size = *off;
    FS_specific_inode->file_size = *off;

    // Sincronizza le modifiche
    mark_inode_dirty(the_inode);
    mutex_unlock(&mutex);
    

    return ret;
}

//look up goes in the inode operations
const struct inode_operations onefilefs_inode_ops = {
    .lookup = onefilefs_lookup,
};

const struct file_operations onefilefs_file_operations = {
    .owner = THIS_MODULE,
    .read = onefilefs_read,
    .write_iter = onefilefs_append
};
