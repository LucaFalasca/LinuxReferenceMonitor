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
    int scelta;
    char *input_password;
    char path[128];
    int ret;
    int stop = 0;

    while (!stop) {
        scelta = -1;
        // Stampa del menu
        printf("\n--- Menu Operazioni ---\n");
        printf("1. Change state\n");
        printf("2. Protect file\n");
        printf("3. Unprotect file\n");
        printf("0. Exit\n");
        printf("Choose operation: ");
        scanf("%d", &scelta);

        switch (scelta) {
            case 1:
                printf("Available states: \n");
                printf("0. OFF\n");
                printf("1. ON\n");
                printf("2. REC_ON\n");
                printf("3. REC_OFF\n");
                printf("Choose state: ");
                scanf("%d", &scelta);
                ret = switch_state(scelta);
                if(ret == -1){
                    printf("Error changing state\n");
                }else{
                    printf("State changed to");
                    if(scelta == 0){
                        printf(" OFF\n");
                    }else if(scelta == 1){
                        printf(" ON\n");
                    }else if(scelta == 2){
                        printf(" REC_ON\n");
                    }else if(scelta == 3){
                        printf(" REC_OFF\n");
                    }
                }
                break;
            case 2:
                input_password = getpass("Insert password: ");
                printf("Insert path: ");
                ret = scanf("%s", path);
                if(ret == 1){
                    ret = protect_path(path, input_password);
                    if(ret == -1){
                        printf("Error protecting path\n");
                    }
                }
                else{
                    printf("Error reading path\n");
                }
                
                break;
            case 3:
                input_password = getpass("Insert password: ");
                printf("Insert path: ");
                ret = scanf("%s", path);
                if(ret == 1){
                    ret = unprotect_path(path, input_password);
                    if(ret == -1){
                        printf("Error deprotecting path\n");
                    }
                }
                else{
                    printf("Error reading path\n");
                }
                break;
            case 0:
                printf("Exiting...\n");
                stop = 1;
                break;
            default:
                printf("Choose not valid, try again.\n");
        }
    }

    return 0;
}

