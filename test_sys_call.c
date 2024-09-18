#include <unistd.h>

int main(int argc, char** argv){
	syscall(156, 1);
    syscall(174, 10);
}