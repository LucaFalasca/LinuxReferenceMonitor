#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h> 


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
    printf("number: %d\n", atoi(buffer));
    int sys_call_entry = atoi(buffer);
    return sys_call_entry;
}

int switch_state(int param){
    int entry = get_sys_call_entry("/sys/module/the_rm_file_protection/parameters/sys0");
    if(entry == -1){
        printf("Error getting sys call entry\n");
        return -1;
    }
    syscall(entry, param);
    return 0;
}

int protect_path(char *path, char* password){
    int entry = get_sys_call_entry("/sys/module/the_rm_file_protection/parameters/sys1");
    if(entry == -1){
        printf("Error getting sys call entry\n");
        return -1;
    }
    syscall(entry, path, password);
    return 0;
}

int unprotect_path(char *path, char *password){
    int entry = get_sys_call_entry("/sys/module/the_rm_file_protection/parameters/sys2");
    if(entry == -1){
        printf("Error getting sys call entry\n");
        return -1;
    }
    syscall(entry, path, password);
    return 0;
}

int main(int argc, char** argv){
    int state = argc > 1 ? atoi(argv[1]) : 0;
    char *password;
    //alloco memoria per la password
    password = (char *) malloc(sizeof(int) * 128);
    if (argc > 2){
        password = argv[2];
    }
    else{
        printf("Password not inserted\n");
        return -1;
    }
	//switch_state(state);

    protect_path("/path/di/prova", password);
    unprotect_path("/path/di/prova", password);
    return 0;
}

