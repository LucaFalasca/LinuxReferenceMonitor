#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h> 
#include <string.h>
#include "rm_syscall.h"

int main(int argc, char** argv){
    int scelta;
    char *input_password;
    char *new_password;
    char *password;
    char path[128];
    int ret;
    int stop = 0;
    int state;

    if (getuid() != 0) {
        printf("The program must be launched with administrator privileges\n");
        exit(1);
    } 

    while (!stop) {
        scelta = -1;
        // Stampa del menu
        printf("\nCurrent state:");
        state = get_state();
        if(state == 0){
            printf(" OFF\n");
        }else if(state == 1){
            printf(" ON\n");
        }else if(state == 2){
            printf(" REC_ON\n");
        }else if(state == 3){
            printf(" REC_OFF\n");
        }
        printf("\n--- Operation Menu ---\n");
        printf("1. Change state\n");
        printf("2. Protect file\n");
        printf("3. Unprotect file\n");
        printf("4. Change password\n");
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

            case 4:
                password = getpass("Insert old password: ");
                input_password = malloc(strlen(password) + 1);
                strcpy(input_password, password);
                password = getpass("Insert new password: ");
                new_password = malloc(strlen(password) + 1);
                strcpy(new_password, password);
                printf("input_password: %s\n", input_password);
                printf("new_password: %s\n", new_password);
                ret = change_password(input_password, new_password);
                if(ret == -1){
                    printf("Error changing password\n");
                }
                break;
            case 0:
                printf("Exiting...\n");
                stop = 1;
                break;
            default:
                printf("Choose not valid, try again.\n");
        }
        printf("Press enter to continue...");
        getchar();
        getchar();
        system("clear");
    }

    return 0;
}

