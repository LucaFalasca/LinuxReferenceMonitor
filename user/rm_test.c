#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h> 
#include <string.h>
#include <sys/stat.h>
#include "rm_syscall.h"


#define FILE_PATH "test_folder/test_file.txt"
#define FOLDER_PATH "test_folder"
#define SYMLINK_PATH "test_folder/sym_link_file.txt"
#define HARDLINK_PATH "test_folder/hard_link_file.txt"
#define FOLDER_INSIDE_PATH "test_folder/test_folder_inside"

int main(int argc, char *argv[])
{
    if (getuid() != 0) {
        printf("The program must be launched with administrator privileges\n");
        exit(1);
    } 

    // Get the reference monitor passoword from the user
    char *password;
    password = getpass("Insert the reference monitor password:");
    int ret;
    char new_file_path[128];
    int fd;

    // get the absolute path of the file and the folder
    char *file_path = realpath(FILE_PATH, NULL);
    char *folder_path = realpath(FOLDER_PATH, NULL);
    char *symlink_path = realpath(SYMLINK_PATH, NULL);
    char *hardlink_path = realpath(HARDLINK_PATH, NULL);
    char *folder_inside_path = realpath(FOLDER_INSIDE_PATH, NULL);
    
    
    printf("\nFILE TESTS\n");

    // Protect the file
    printf("Protecting file %s\n", file_path);
    ret = protect_path(file_path, password);
    if(ret == -1){
        printf("Error protecting path\n");
        exit(1);
    }
    
    // Test the removing of the file
    printf("Removing file test: ");
    ret = remove(file_path);
    if(ret == -1){
        printf("Test passed\n");
    }else{
        printf("Test failed\n");
        return 1;
    }

    // Test the writing of the file
    printf("Writing file test: ");
    fd = open(file_path, O_WRONLY | O_CREAT, 0666);
    if(fd == -1){
        printf("Test passed\n");
    }else{
        printf("Test failed\n");
        return 1;
    }

    // Test the renaming of the file
    printf("Renaming file test: ");
    strcpy(new_file_path, file_path);
    strcat(new_file_path, "_new");
    ret = rename(file_path, new_file_path);
    if(ret == -1){
        printf("Test passed\n");
    }else{
        printf("Test failed\n");
        return 1;
    }

    // Test the unlinking of the file
    printf("Unlinking file test: ");
    ret = unlink(file_path);
    if(ret == -1){
        printf("Test passed\n");
    }else{
        printf("Test failed\n");
        return 1;
    }


    // Test the writing on existing symlink of the file
    printf("symlink file test: ");
    fd = open(symlink_path, O_WRONLY | O_CREAT, 0666);
    if(fd == -1){
        printf("Test passed\n");
    }else{
        printf("Test failed\n");
        return 1;
    }
    
    // Test the writing on existing hardlink of the file
    printf("hardlink file test: ");
    fd = open(hardlink_path, O_WRONLY | O_CREAT, 0666);
    if(fd == -1){
        printf("Test passed\n");
    }else{
        printf("Test failed\n");
        return 1;
    }

    // Unprotect the file
    printf("Unprotecting file %s\n", file_path);
    ret = unprotect_path(file_path, password);
    
    printf("\nFOLDER TESTS\n");

    // Protect the folder
    printf("Protecting folder %s\n", folder_path);
    ret = protect_path(folder_path, password);
    if(ret == -1){
        printf("Error protecting path\n");
        exit(1);
    }

    
    // Test the removing of the folder
    printf("Removing folder test: ");
    ret = remove(folder_path);
    if(ret == -1){
        printf("Test passed\n");
    }else{
        printf("Test failed\n");
        return 1;
    }

    // Test the writing of the folder
    printf("Writing folder test: ");
    fd = open(folder_path, O_WRONLY | O_CREAT, 0666);
    if(fd == -1){
        printf("Test passed\n");
    }else{
        printf("Test failed\n");
        return 1;
    }

    // Test the renaming of the folder
    printf("Renaming folder test: ");
    char new_folder_path[128];
    strcpy(new_folder_path, folder_path);
    strcat(new_folder_path, "/new_folder");
    ret = rename(folder_path, new_folder_path);
    if(ret == -1){
        printf("Test passed\n");
    }else{
        printf("Test failed\n");
        return 1;
    }

    // Test the unlinking of the folder
    printf("Unlinking folder test: ");
    ret = unlink(folder_path);
    if(ret == -1){
        printf("Test passed\n");
    }else{
        printf("Test failed\n");
        return 1;
    }

    // Create a new file in the folder
    printf("Creating new file test: ");
    fd = open(new_file_path, O_WRONLY | O_CREAT, 0666);
    if(fd == -1){
        printf("Test passed\n");
    }else{
        printf("Test failed\n");
        return 1;
    }

    // Delete a file in the folder
    printf("Deleting file test: ");
    ret = unlink(new_file_path);
    if(ret == -1){
        printf("Test passed\n");
    }else{
        printf("Test failed\n");
        return 1;
    } 

    // Create a new folder in the folder
    printf("Creating new folder test: ");
    ret = mkdir(new_folder_path, 0777);
    if(ret == -1){
        printf("Test passed\n");
    }else{
        printf("Test failed\n");
        return 1;
    }

    // Delete a folder in the folder
    printf("Deleting folder test: ");
    ret = rmdir(folder_inside_path);
    if(ret == -1){
        printf("Test passed\n");
    }else{
        printf("Test failed\n");
        return 1;
    }
    
    

    // Unprotect the folder
    printf("Unprotecting folder %s\n", folder_path);
    ret = unprotect_path(folder_path, password);
    if(ret == -1){
        printf("Error unprotecting path\n");
        exit(1);
    }
    

    return 0;
}