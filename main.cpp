#include <stdio.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <assert.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/uio.h>
using namespace std;

typedef unsigned int UINT;

#define STR_MAX 2048
const char *libName="../lib.so";  //this is the library we are going to inject

void dump(pid_t tid,int start=-3,int end=3)
{
    //debug this as well
    user uregs={};
    auto er=ptrace(PTRACE_GETREGS,tid,NULL,&uregs);

    unsigned char data=3;
    for(int i=start;i<end;++i)
    {
        data=ptrace(PTRACE_PEEKTEXT,tid,uregs.regs.rip-i,&data);
        unsigned int ui=data;
        printf("RIP:%lx %x\n",uregs.regs.rip-i,ui);
    }
}

void *FindSoAddress(const char *strLibName,pid_t pid) //all this to defeat ASLR
{
    char str[STR_MAX]="";
    sprintf(str,"/proc/%d/maps",pid);

    FILE *fp=fopen(str,"r");
    void *pAddress=NULL;
    if(fp)
    {
        char buffer[STR_MAX]={};
        while( fgets(buffer,sizeof(buffer),fp))
        {
            if(strstr(buffer,strLibName))
            {
                //found library, extract the base address
                pAddress = (void*)strtoul( buffer, NULL, 16 );
                break;
            }
        }
        fclose(fp);
    }
    return pAddress;
}

void *FindFuncAddr(const char *strLibName,const void *pLocalFuncAddr,pid_t pid)  //lets defeat ASLR
{
    void *pbLibRemoteAddr=FindSoAddress(strLibName,pid);
    void *pbLibLocal_Addr=FindSoAddress(strLibName,getpid());

    //now to find the function
    if(pbLibRemoteAddr && pbLibLocal_Addr){
        unsigned long int offset=(unsigned long int)pLocalFuncAddr-(unsigned long int)pbLibLocal_Addr;
        return pbLibRemoteAddr+offset;
    }
    else
        return NULL;
}


unsigned char OrignalData[50]={};
void ReadProcessMemory(unsigned int rpid,user uregs)
{
    iovec Originaliovec,remote_iov;
    Originaliovec.iov_base=OrignalData;
    Originaliovec.iov_len=sizeof(OrignalData);

    remote_iov.iov_base=uregs.regs.rip;
    remote_iov.iov_len=sizeof(OrignalData);

    size_t y=process_vm_readv(rpid,&Originaliovec,1,&remote_iov,1,0);
    if(50!=y)
    {
        ptrace(PTRACE_CONT, rpid, NULL,0);  //let the tracee continue, if you dont, then tracer will kill the tracee
        exit(0);
    }

    //  printf("********************\n");
    //  for(int i=0;i<sizeof(OrignalData);++i)
    //      printf("%llu %llx:%x %c \n",uregs.regs.rip+i,uregs.regs.rip+i,(UINT)OrignalData[i],OrignalData[i]);
}

void RestoreMemory(pid_t rpid,user originalRegs)
{
    for(int i=0;i<sizeof(OrignalData);++i)
        ptrace(PTRACE_POKETEXT,rpid,originalRegs.regs.rip+i,OrignalData[i]);

    ptrace(PTRACE_SETREGS,rpid,NULL,&originalRegs);
}

unsigned char data_opcodes[50]={};
void WriteProcessMemory(const unsigned int rpid,user uregs={})
{
    const char *str = libName;
    memcpy(data_opcodes, str,strlen(str)+1);  //copied the name of the so

    unsigned char MovRaxtoRDI[] = { 0x48, 0x8B, 0xf8 };  //these are the opcodes for move RAX=>RDI
    unsigned char Mov1toRBX[] = { 0x48, 0xc7, 0xc3, 01, 0, 0, 0 };   //move 1=RBX
    unsigned char MovRBXtoRSI[] = { 0x48, 0x8B, 0xF3 };              //move RBX=>RSI
    unsigned char CallRax[] = {0xff, 0xd0, 0xcc };  //Call RAX and then break (int 3)

    //compine all the opcodes
    unsigned char opcodes[50];

    //copy the address of the lib file to RAX, we are placing the lib.so file after all the opcodes (including the breakpoint)
    //so the flow is (intel assembly format):
    /*
     * mov rax,address of the so file       (1)
     * mov rdi,rax                          (2)
     * mov rbx,1                            (3)
     * mov rsi,rbx                          (4)
     * mov rax,function address of dlopen   (5)
     * call RAX                             (6)
     * breakpoint
     * .
     * .
     * /
     * /
     * l
     * i
     * b
     * .
     * s
     * o
     */

    /*(1)*/unsigned char MovtoRax[2 + 8] = { 0x48, 0xb8 };
    void *p = uregs.regs.rip+sizeof(MovtoRax) + sizeof(MovRaxtoRDI) + sizeof(Mov1toRBX) + sizeof(MovRBXtoRSI) + sizeof(MovtoRax) + sizeof(CallRax);
    memcpy(&MovtoRax[2], &p, 8);
    memcpy(opcodes, MovtoRax, sizeof(MovtoRax));  //move first paramter to RAX-> then to RDI

    /*(2)*/memcpy(opcodes + sizeof(MovtoRax), MovRaxtoRDI, sizeof(MovRaxtoRDI));
    /*(3)*/memcpy(opcodes + sizeof(MovtoRax) + sizeof(MovRaxtoRDI), Mov1toRBX, sizeof(Mov1toRBX));  //move second parameter to RBX  -> then to RSI
    /*(4)*/memcpy(opcodes + sizeof(MovtoRax) + sizeof(MovRaxtoRDI) + sizeof(Mov1toRBX), MovRBXtoRSI, sizeof(MovRBXtoRSI));

    /*(5)*/
    p = FindFuncAddr("libdl",dlopen,rpid);  //find out where libdl is loaded in the remote process, this is randomly loaded for every process (thanks to ASLR)
    printf("remote address for dlopen %lx\n",p);

    memcpy(&MovtoRax[2], &p, 8);  //move function address to RAX->call RAX
    memcpy(opcodes + sizeof(MovtoRax) + sizeof(MovRaxtoRDI) + sizeof(Mov1toRBX) + sizeof(MovRBXtoRSI), MovtoRax, sizeof(MovtoRax));

    /*(6)*/memcpy(opcodes + sizeof(MovtoRax) + sizeof(MovRaxtoRDI) + sizeof(Mov1toRBX) + sizeof(MovRBXtoRSI) + sizeof(MovtoRax), CallRax, sizeof(CallRax));
    memcpy(data_opcodes, opcodes, sizeof(MovtoRax) + sizeof(MovRaxtoRDI) + sizeof(Mov1toRBX) + sizeof(MovRBXtoRSI) + sizeof(MovtoRax) + sizeof(CallRax));

    memcpy(data_opcodes+sizeof(MovtoRax) + sizeof(MovRaxtoRDI) + sizeof(Mov1toRBX) + sizeof(MovRBXtoRSI) + sizeof(MovtoRax) + sizeof(CallRax),
           str,strlen(str)+1);

    //now write these opcodes to the remote process.
    for(int i=0;i<sizeof(data_opcodes);++i){
        ptrace(PTRACE_POKETEXT,rpid,uregs.regs.rip+i,data_opcodes[i]);
    }

    printf("inside WriteProcessMemory setting RIP:%lx\n",uregs.regs.rip);
    ptrace(PTRACE_SETREGS,rpid,NULL,&uregs);
}



int main()
{
    printf("By Asif Bahrainwala, asif_bahrainwala@hotmail.com \nppid:%x %u\n",::getpid(),::getpid());  //this is important :-)

    unsigned int rpid=0;
    switch(rpid = fork())  //spqwn a process
    {
    case 0://child process
    {
        int y=execlp("../build-QTUI_App-Desktop_Qt_5_11_2_GCC_64bit-Debug/QTUI_App",0);
        //int y=execlp("../build-Test-Desktop_Qt_5_11_2_GCC_64bit-Debug/Test",0);
        break;
    }
    case -1:
        printf("error spawning process\n");exit(-1);
        break;
        //parent continues execution
    }

    sleep(3);//give it time

    printf("pid of remote process:%u\n",rpid);

    int status=0;
    ptrace(PTRACE_ATTACH,rpid,NULL);printf("error %u\n",errno);   //lets attach the process
    pid_t tid=wait(&status);
    /*PTRACE_ATTACH
                     Attach to the process specified in pid, making it a tracee of the calling process.  The tracee is sent a SIGSTOP, but will not  necessar‐
                     ily  have  stopped by the completion of this call; use waitpid(2) to wait for the tracee to stop.  See the "Attaching and detaching" sub‐
                     section for additional information.  (addr and data are ignored.)
        */
    ptrace(PTRACE_SETOPTIONS, tid, NULL, PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT);

    user originalRegs={};

    while(1)
    {
        if(WIFSTOPPED(status))
        {
            printf("child has stopped \n");

            siginfo_t siginfo={};
            ptrace(PTRACE_GETSIGINFO,tid,NULL,&siginfo);
            printf("signal caught:%u\n",siginfo.si_signo);

            if(siginfo.si_signo == 11)
            {
                //some error has happened
                printf("segv! abort\n");
                dump(tid);
                kill(rpid,9);
                exit(0);
            }
            if(siginfo.si_signo==5)  //SIGTRAP found
            {
                printf("before mem restore\n");
                dump(tid);

                RestoreMemory(rpid,originalRegs);
                ptrace(PTRACE_DETACH,tid,0,0);  //it will detach If  the  tracer  dies,  all  tracees  are  automatically  detached  and restarted, unless they were in group-stop.
                sleep(2);
                exit(0);//your work is done
            }

            if(originalRegs.regs.rip==0)
            {
                ptrace(PTRACE_SINGLESTEP, tid, 0, 0);  //let it continue one step
                tid=waitpid(-1, &status, __WALL);

                user uregs={};
                ptrace(PTRACE_GETREGS,tid,NULL,&uregs);

                printf("tracee stoped RIP:%lx\n",uregs.regs.rip);

                size_t sztest=((0x1000+uregs.regs.rip&0xfffffffffffff000)-uregs.regs.rip);  //to find out how many bytes of memory from current EIP to page-end boundary
                if(sztest<50+10)  //10 bytes extra to be safe
                {
                    printf("Could not attach, not enough memory to implant my opcodes, try again!\n");
                    ptrace(PTRACE_DETACH,tid,0,0);
                    exit(0);
                }
                else
                {
                    printf("testing (only) %lx\n",sztest);fflush(stdout);
                }
                originalRegs=uregs;  //do this once
                ReadProcessMemory(tid,uregs);
                WriteProcessMemory(tid,uregs);
            }
           /*
                 * long ptrace(enum __ptrace_request request, pid_t pid,
                       void *addr, void *data);

                 * PTRACE_CONT
                              Restart  the  stopped tracee process.  If data is nonzero, it is interpreted as the number of a signal to be delivered to the tracee;
                              otherwise, no signal is delivered.  Thus, for example, the tracer can control whether a signal sent to the  tracee  is  delivered  or
                              not.  (addr is ignored.)
            */

            //below is step wise debugging
            for(int i=0;i<20 ;++i){ //run 20 instructions
                printf("go %d step\n",i);
                dump(tid,-3,3);
                ptrace(PTRACE_SINGLESTEP, tid, 0, 0);  //let it continue one step
                tid=waitpid(-1, &status, __WALL);
            }
            for(unsigned char c:data_opcodes)
            {
                printf("%x ",(unsigned int)c);
            }
            printf("\n");

            ptrace(PTRACE_CONT, tid, NULL,0);  //lets not send any signals back to the tracee
        }
        tid=waitpid(-1, &status, __WALL);
    }

    return 0;
}

