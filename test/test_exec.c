#include <stdio.h>
#include <stdlib.h>


int exec0(){
    char *args[] = {"u8f2_tc",NULL };
    int pid = fork();
    if(pid ==0 ){
        if (execve("/tmp/u8f2_tc", args, NULL) == -1) {
            perror("execve");
            return 1;
        }
    }

    return 0;
}


int main(int argc,char **argv){
    int choice;
    // if(argc < 2){
    //     return 0;
    // }
    exec0();
    // choice = atoi(argv[1]);
    // switch(choice){
    //     case 0:
    //         exec0();
    //         break;
    // }
    return 0;
}