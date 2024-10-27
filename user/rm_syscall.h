int get_sys_call_entry(char *entry_path){
    int fd = open(entry_path, O_RDONLY);
    if(fd == -1){
        printf("Error opening file\n");
        return -1;
    }
    ssize_t bytesRead;
    char buffer[16];
    bytesRead = read(fd, buffer, sizeof(buffer));
    if(bytesRead == -1){
        printf("Error reading file\n");
        return -1;
    }
    buffer[bytesRead] = '\0';
    close(fd);
    //printf("number: %d\n", atoi(buffer));
    int sys_call_entry = atoi(buffer);
    return sys_call_entry;
}

int switch_state(int param){
    int entry = get_sys_call_entry("/sys/module/the_rm_file_protection/parameters/sys0");
    if(entry == -1){
        printf("Error getting sys call entry\n");
        return -1;
    }
    return syscall(entry, param);
}

int protect_path(char *path, char* password){
    int entry = get_sys_call_entry("/sys/module/the_rm_file_protection/parameters/sys1");
    if(entry == -1){
        printf("Error getting sys call entry\n");
        return -1;
    }
    return syscall(entry, path, password);
}

int unprotect_path(char *path, char *password){
    int entry = get_sys_call_entry("/sys/module/the_rm_file_protection/parameters/sys2");
    if(entry == -1){
        printf("Error getting sys call entry\n");
        return -1;
    }
    return syscall(entry, path, password);
}

int change_password(char *old_password, char *new_password){
    int entry = get_sys_call_entry("/sys/module/the_rm_file_protection/parameters/sys3");
    if(entry == -1){
        printf("Error getting sys call entry\n");
        return -1;
    }
    return syscall(entry, old_password, new_password);
}

int get_state(){
    int entry = get_sys_call_entry("/sys/module/the_rm_file_protection/parameters/state");
    if(entry == -1){
        printf("Error getting sys call entry\n");
        return -1;
    }
    return entry;
}