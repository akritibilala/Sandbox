  #include <sys/ptrace.h>
  #include <sys/user.h>
  #include <fnmatch.h>
  #include <stdlib.h>
  #include <stdio.h>
  #include <err.h>
  #include <string.h>
  #include <sys/reg.h>
  #include <sys/syscall.h>
  #include <signal.h>
  #include <ctype.h>
  #include <errno.h>
  #include <fcntl.h>
  #include <limits.h>
  #include <libgen.h>
  #include <unistd.h>
  #include <sys/types.h>
  #include <sys/wait.h>
  

  const int size = sizeof(long);

  struct sandbox{

  	pid_t child;
  	const char *name; 
  }; 


void getdata(pid_t child, long addr,
               char *str, int len)
  {   char *laddr;
    
      int i, j;
     long val;
      i = 0;
      j = len / size;
      laddr = str;
      
      while(i < j) {
          val = ptrace(PTRACE_PEEKDATA,
                            child, addr + i * 8,
                            NULL);
          memcpy(laddr, &val, size);
          ++i;
          laddr += size;
      }
      j = len % size;
      str[len] = '\0';
    
  }


  void sandbox_initialization(struct sandbox *sb, char **argv, char *config){

  pid_t  pid;  
  pid = fork();
  char buff[255];
  char*fp;
  char loc[255];
  int permission, current;
  int  arr[3],i;

    if(pid == -1)
      err(EXIT_FAILURE, "[SANDBOX] Error on fork:");

    if(pid == 0) {

      if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
       { err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_TRACEME:"); }
      
      if(execv(argv[0], argv) < 0)
       { err(EXIT_FAILURE, "[SANDBOX] Failed to execv:");
         }
 
              
  
  }
   else {
      sb->child = pid;
      sb->name = argv[0];
     }
}
  void sandbox_run(struct sandbox *sb, char *config)
  {
    
     
     int n, arr[3],i;
     
     int permission, current;
    char buf[PATH_MAX + 1]; 
          int status;
          char cwd[1024];
        char *str; char *temp; char buff[255];
              long orig_eax,rdi,rsi,rdx; FILE *fp;
        int check = 0, check1=0, check2=0, check3=0, check4=0, check5=0,flag=0; char loc[255]; 
       

    while(1) {
           wait(&status);
           if(WIFEXITED(status))
               exit(EXIT_SUCCESS);
           orig_eax = ptrace(PTRACE_PEEKUSER,
                             sb->child, 8 * ORIG_RAX,
                             NULL);
          
           if(orig_eax == SYS_open) {
              if(check == 0) {
                 check = 1;
                 rdi = ptrace(PTRACE_PEEKUSER,
                                    sb->child, 8 * RDI,
                                    NULL);
                 rsi = ptrace(PTRACE_PEEKUSER,
                                    sb->child, 8 * RSI,
                                    NULL);
                 rdx = ptrace(PTRACE_PEEKUSER,
                                    sb->child, 8 * RDX,
                                    NULL);
                 str = (char *)calloc((1000)
                                   , sizeof(char));
                    
                 getdata(sb->child, rdi, str, 100);
                 if (realpath(str, buf)==NULL)
                  { 
                   temp= strdup(str);
                   str= dirname(temp);
 
 
                  }
                
     fp = NULL;  
      
     fp = fopen(config, "r");  
    if(fp==NULL){
           
        exit(1);             
    }
    while(1){
     fscanf(fp, "%s", buff);
     if(feof(fp)) {break;}
     
   

    permission=atoi(buff);
    current=permission;

    fscanf(fp, "%s", buff);
    
    if(fnmatch(buff,str,FNM_NOESCAPE)==0){
          strcpy(loc,buff);
          current=permission;
      }

   }
   fclose(fp);

  for (i = 2; i >= 0; i--)
     {
        arr[i]=current%10;
        current/=10;
     }

  
     
                 
                 
                flag=0;
                  if((rsi & O_RDWR) == O_RDWR && arr[0]==1 && arr[1]==1 && flag==0)
                  { 
                    flag= 1;
                  }
                
                  if ((rsi & O_WRONLY) == O_WRONLY && arr[1]==1 && flag==0)
                  {
                    flag=1;  
                    
                    
                  }
                 
                  if ((rsi & O_RDONLY) == O_RDONLY && arr[0]==1 && flag==0)
                  {
                    flag=1;
                    
                  }

                  if(flag==0){

                     printf("Terminating fend: unauthorized access of %s\n", str);
                    exit(EXIT_FAILURE);

                  }
                  
                  if ((rsi & O_TRUNC) == O_TRUNC && arr[0]==1  && arr[1]==1 )
                  {
                    
                  }
                  else{
                    if(((rsi & O_TRUNC) == O_TRUNC && arr[0]!=1  && arr[1]!=1)||((rsi & O_TRUNC) == O_TRUNC && arr[0]==1  && arr[1]!=1 )||((rsi & O_TRUNC) == O_TRUNC && arr[0]!=1  && arr[1]==1 )){
                    printf("Terminating fend: unauthorized access of %s\n", str);
                    exit(EXIT_FAILURE);
                  }
                  else{

                  }
                  }

                   if ((rsi & O_APPEND) == O_APPEND && arr[0]==1  && arr[1]==1 )
                  {
                    
                  }
                  else{
                    if(((rsi & O_APPEND) == O_APPEND && arr[0]!=1  && arr[1]!=1)||((rsi & O_APPEND) == O_APPEND && arr[0]==1  && arr[1]!=1 )||((rsi & O_APPEND) == O_APPEND && arr[0]!=1  && arr[1]==1 )){
                    printf("Terminating fend: unauthorized access of %s\n", str);
                    exit(EXIT_FAILURE);
                  }
                  else{
                    
                  }
                  }
                  if((rsi & O_CREAT)== O_CREAT)
                    { 
                     if (realpath(str, buf)==NULL) {
                     }
                     fp = fopen(config, "r");  
    if(fp==NULL){
        exit(1);             
    }
    while(1){
     fscanf(fp, "%s", buff);
     if(feof(fp)) {break;}
     
   

    permission=atoi(buff);
    current=permission;
    fscanf(fp, "%s", buff);


    if(fnmatch(buff,str,FNM_NOESCAPE)==0)
     {
        strcpy(loc,buff);
        current=permission;
     }
   }
   fclose(fp);

  for (i = 2; i >= 0; i--)
     {
        arr[i]=current%10;
        current/=10;
     }

  if ((arr[1]!=1 && arr[2]==1)||(arr[1]!=1 && arr[2]!=1)||(arr[1]==1 && arr[2]!=1))
  {
    printf("Terminating fend: unauthorized access of %s\n", str);
    exit(EXIT_FAILURE);
  }
  }
                      if(flag==0)
                    {
                        
                      printf("Terminating fend: unauthorized access of %s\n", str);
                      exit(EXIT_FAILURE);
                  }

                
              }
              else {
                 check = 0;

              }
           }
           if(orig_eax == SYS_openat) {

              if(check5 == 0) {
                 check5 = 1;
                 rdi = ptrace(PTRACE_PEEKUSER,
                                    sb->child, 8 * RDI,
                                    NULL);

                 rsi = ptrace(PTRACE_PEEKUSER,
                                    sb->child, 8 * RSI,
                                    NULL);
                 rdx = ptrace(PTRACE_PEEKUSER,
                                    sb->child, 8 * RDX,
                                    NULL);
                 str = (char *)calloc((1000)
                                   , sizeof(char));
                      getdata(sb->child, rsi, str, 100);
                 
                 if (realpath(str, buf)!=NULL)
                  { 
                    
                   temp= strdup(str);
                   str= dirname(temp);
 
 
                  }
                
     fp = NULL;  
       
     fp = fopen(config, "r");  
    if(fp==NULL){
           
        exit(1);             
    }
    while(1){
     fscanf(fp, "%s", buff);
     if(feof(fp)) {break;}
     
   

    permission=atoi(buff);
  current=permission;
    fscanf(fp, "%s", buff);
    
    if(fnmatch(buff,str,FNM_NOESCAPE)==0){
          strcpy(loc,buff);
            current=permission;
      }

   }
   fclose(fp);

  for (i = 2; i >= 0; i--)
     {
        arr[i]=current%10;
        current/=10;
     }

 
     
                 flag=0;
                 
                
                  
                  if((rsi & O_RDWR) == O_RDWR && arr[0]==1 && arr[1]==1 && flag==0)
                  {
                    flag= 1; 
                      
                    
                  }
                
                  if ((rsi & O_WRONLY) == O_WRONLY && arr[1]==1 && flag==0)
                  {
                    flag=1;  
                    
                    
                  }
                 
                  if ((rsi & O_RDONLY) == O_RDONLY && arr[0]==1 && flag==0)
                  {
                    flag=1;
                    
                  }
                  if(flag==0){

                     printf("Terminating fend: unauthorized access of %s\n", str);
                    exit(EXIT_FAILURE);

                  }
                  
                  if ((rsi & O_TRUNC) == O_TRUNC && arr[0]==1  && arr[1]==1 )
                  {
                    
                    
                  }
                  else{
                    if(((rsi & O_TRUNC) == O_TRUNC && arr[0]!=1  && arr[1]!=1)||((rsi & O_TRUNC) == O_TRUNC && arr[0]==1  && arr[1]!=1 )||((rsi & O_TRUNC) == O_TRUNC && arr[0]!=1  && arr[1]==1 )){
                    printf("Terminating fend: unauthorized access of %s\n", str);
                    exit(EXIT_FAILURE);
                  }
                  else{

                  }
                  }

                   if ((rsi & O_APPEND) == O_APPEND && arr[0]==1  && arr[1]==1 )
                  {
                    
                  }
                  else{
                    if(((rsi & O_APPEND) == O_APPEND && arr[0]!=1  && arr[1]!=1)||((rsi & O_APPEND) == O_APPEND && arr[0]==1  && arr[1]!=1 )||((rsi & O_APPEND) == O_APPEND && arr[0]!=1  && arr[1]==1 )){
                    printf("Terminating fend: unauthorized access of %s\n", str);
                    exit(EXIT_FAILURE);
                  }
                  else{
                    
                  }
                  }
                  if((rsi & O_CREAT)== O_CREAT)
                    { 
                     if (realpath(str, buf)==NULL) {
                        
                     }
                     fp = fopen(config, "r");  
    if(fp==NULL){
           
        exit(1);             
    }
    while(1){
     fscanf(fp, "%s", buff);
     if(feof(fp)) {break;}
     
   

    permission=atoi(buff);
    current=permission;
    fscanf(fp, "%s", buff);


    if(fnmatch(buff,str,FNM_NOESCAPE)==0)
     {
        strcpy(loc,buff);
        current=permission;
     }
   }
   fclose(fp);

  for (i = 2; i >= 0; i--)
     {
        arr[i]=current%10;
        current/=10;
     }

  if ((arr[1]!=1 && arr[2]==1)||(arr[1]!=1 && arr[2]!=1)||(arr[1]==1 && arr[2]!=1))
  {
    printf("Terminating fend: unauthorized access of %s\n", str);
    exit(EXIT_FAILURE);
  }
  }
                      if(flag==0)
                    {
                        
                      printf("Terminating fend: unauthorized access of %s\n", str);
                      exit(EXIT_FAILURE);
                      
                  }

                
              }
              else {
                 check5 = 0;

              }
           }
        
         


           if(orig_eax == SYS_mkdir || orig_eax == SYS_mkdirat ) {
              if(check1 == 0) {
                 check1= 1;
                 rdi = ptrace(PTRACE_PEEKUSER,
                                    sb->child, 8 * RDI,
                                    NULL);
                 rsi = ptrace(PTRACE_PEEKUSER,
                                    sb->child, 8 * RSI,
                                    NULL);
                 rdx = ptrace(PTRACE_PEEKUSER,
                                    sb->child, 8 * RDX,
                                    NULL);
                 str = (char *)calloc((1000)
                                   , sizeof(char));

                 getdata(sb->child, rdi, str, 100);
                 




                if (realpath(str, buf)==NULL)
                  { 
                    
                   temp= strdup(str);
                   str= dirname(temp);
 
 
                  }
                else { 
                  str=getcwd(cwd, sizeof(cwd));
                }



                    fp=NULL;  
       
     fp = fopen(config, "r");  
    if(fp==NULL){
           
        exit(1);             
    }
    while(1){
     fscanf(fp, "%s", buff);
     if(feof(fp)) {break;}
     
   

    permission=atoi(buff);
    fscanf(fp, "%s", buff);


    if(fnmatch(buff,str,FNM_NOESCAPE)==0)
     {
        strcpy(loc,buff);
        current=permission;
     }
   }
   fclose(fp);

  for (i = 2; i >= 0; i--)
     {
        arr[i]=current%10;
        current/=10;
     }

                if(  arr[1]==1 && flag==0 && arr[2]==1)
                 {
                    flag=1;
                    

                 }
                 else if(flag==0){
                  printf("Terminating fend: unauthorized access of %s\n", str);
                  exit(EXIT_FAILURE);
                    }
                 }
                else  {
                 check1 = 0; }
       }

            if(orig_eax == SYS_rename || orig_eax == SYS_renameat) {
              if(check2 == 0) {
                 check2= 1;
                 rdi = ptrace(PTRACE_PEEKUSER,
                                    sb->child, 8 * RDI,
                                    NULL);
                 rsi = ptrace(PTRACE_PEEKUSER,
                                    sb->child, 8 * RSI,
                                    NULL);
                 rdx = ptrace(PTRACE_PEEKUSER,
                                    sb->child, 8 * RDX,
                                    NULL);
                 str = (char *)calloc((1000)
                                   , sizeof(char));

                 getdata(sb->child, rdi, str, 100);

                  
                    

                  if (realpath(str, buf)!=NULL)
                  { 
                    temp= strdup(buf);
                   str= dirname(temp);
                    }

                    fp=NULL;  
   
     fp = fopen(config, "r");  
    if(fp==NULL){
           
        exit(1);             
    }
    while(1){
     fscanf(fp, "%s", buff);
     if(feof(fp)) {break;}
     
   

    permission=atoi(buff);
    current=permission;
    fscanf(fp, "%s", buff);


    if(fnmatch(buff,str,FNM_NOESCAPE)==0)
     {
        strcpy(loc,buff);
        current=permission;
     }
   }
   fclose(fp);

  for (i = 2; i >= 0; i--)
     {
        arr[i]=current%10;
        current/=10;
     }

 if (arr[1]==1 &&  arr[2]==1)
                  {
                    flag=1;  
                    
                    
                  } 

                  else 
                  { 
                     printf("Terminating fend: unauthorized access of %s\n", str);
                     exit(EXIT_FAILURE);
                      
                  }             
                       str=NULL;
                        temp=NULL; 
                       
                         permission=0; 
                         
                 getdata(sb->child, rsi, str, 100);

                   
                    

                  if (realpath(str, buf)!=NULL)
                  { 
                    temp= strdup(buf);
                   str= dirname(temp);
                    }

                    fp=NULL;  
     


     fp = fopen(config, "r");  
    if(fp==NULL){
           
        exit(1);             
    }
    while(1){
     fscanf(fp, "%s", buff);
     if(feof(fp)) {break;}
     
   

    permission=atoi(buff);
    current=permission;
    fscanf(fp, "%s", buff);


    if(fnmatch(buff,str,FNM_NOESCAPE)==0)
     {
        strcpy(loc,buff);
        current=permission;

     }
   }
   fclose(fp);

  for (i = 2; i >= 0; i--)
     {
        arr[i]=current%10;
        current/=10;
     }

 if (arr[1]==1 &&  arr[2]==1)
                  {
                    flag=1;  
                    
                    
                  } 

                  else 
                  { 
                     printf("Terminating fend: unauthorized access of %s\n", str);
                     exit(EXIT_FAILURE);
                    
                  }             
   

   }
 else{

check2=0;

 }

}



         if(orig_eax == SYS_link || orig_eax == SYS_linkat) {
              if(check3 == 0) {
                 check3= 1;
                 rdi = ptrace(PTRACE_PEEKUSER,
                                    sb->child, 8 * RDI,
                                    NULL);
                 rsi = ptrace(PTRACE_PEEKUSER,
                                    sb->child, 8 * RSI,
                                    NULL);
                 rdx = ptrace(PTRACE_PEEKUSER,
                                    sb->child, 8 * RDX,
                                    NULL);
                 str = (char *)calloc((1000)
                                   , sizeof(char));

                 getdata(sb->child, rdi, str, 100);

                  
                    

                  if (realpath(str, buf)!=NULL)
                  {
                    temp= strdup(buf);
                   str= dirname(temp);
                    }

                    fp=NULL;  
     
     fp = fopen(config, "r");  
    if(fp==NULL){
           
        exit(1);             
    }
    while(1){
     fscanf(fp, "%s", buff);
     if(feof(fp)) {break;}
     
   

    permission=atoi(buff);
    current=permission;
    fscanf(fp, "%s", buff);


    if(fnmatch(buff,str,FNM_NOESCAPE)==0)
     {
        strcpy(loc,buff);
        current=permission;
     }
   }
   fclose(fp);

  for (i = 2; i >= 0; i--)
     {
        arr[i]=current%10;
        current/=10;
     }

 if (arr[1]==1 )
                  {
                    flag=1;  
                    
                    
                  } 

                  else 
                  { 
                     printf("Terminating fend: unauthorized access of %s\n", str);
                     exit(EXIT_FAILURE);
                      
                  }             
                       str=NULL;
                        temp=NULL; 
                       
                         permission=0; 
                        
                 getdata(sb->child, rsi, str, 100);

                  
                    

                  if (realpath(str, buf)!=NULL)
                  { 
                    temp= strdup(buf);
                   str= dirname(temp);
                    }

                    fp=NULL;  
      
     fp = fopen(config, "r");  
    if(fp==NULL){
           
        exit(1);             
    }
    while(1){
     fscanf(fp, "%s", buff);
     if(feof(fp)) {break;}
     
   

    permission=atoi(buff);
    current=permission;
    fscanf(fp, "%s", buff);


    if(fnmatch(buff,str,FNM_NOESCAPE)==0)
     {
        strcpy(loc,buff);
        current=permission;
     }
   }
   fclose(fp);

  for (i = 2; i >= 0; i--)
     {
        arr[i]=current%10;
        current/=10;
     }

 if (arr[1]==1)
                  {
                    flag=1;  
                    
                    
                  } 

                  else 
                  { 
                     printf("Terminating fend: unauthorized access of %s\n", str);
                     exit(EXIT_FAILURE);
                    
                  }             
   

   }
 else{

check3=0;

 }

}


if(orig_eax == SYS_unlink) {
              if(check4 == 0) {
                 check4= 1;
                 rdi = ptrace(PTRACE_PEEKUSER,
                                    sb->child, 8 * RDI,
                                    NULL);
                 rsi = ptrace(PTRACE_PEEKUSER,
                                    sb->child, 8 * RSI,
                                    NULL);
                 rdx = ptrace(PTRACE_PEEKUSER,
                                    sb->child, 8 * RDX,
                                    NULL);
                 str = (char *)calloc((1000)
                                   , sizeof(char));

                 getdata(sb->child, rdi, str, 100);

                   
                    

                  if (realpath(str, buf)!=NULL)
                  { 
                    temp= strdup(buf);
                   str= dirname(temp);
                    }

                    fp=NULL;  
      
     fp = fopen(config, "r");  
    if(fp==NULL){
           
        exit(1);             
    }
    while(1){
     fscanf(fp, "%s", buff);
     if(feof(fp)) {break;}
     
   

    permission=atoi(buff);
    current=permission;
    fscanf(fp, "%s", buff);


    if(fnmatch(buff,str,FNM_NOESCAPE)==0)
     {
        strcpy(loc,buff);
        current=permission;
     }
   }
   fclose(fp);

  for (i = 2; i >= 0; i--)
     {
        arr[i]=current%10;
        current/=10;
     }

 if (arr[1]==1 )
                  {
                    flag=1;  
                    
                    
                  } 

                  else 
                  { 
                     printf("Terminating fend: unauthorized access of %s\n", str);
                     exit(EXIT_FAILURE);
                      
                  } 

}
else{

check3=0;

 }
 }
 ptrace(PTRACE_SYSCALL, sb->child, NULL, NULL);


}
}


  



  int main(int argc, char **argv)
  {
  struct sandbox sb;
  char *config;

  if(argc<2)
  {
    errx(EXIT_FAILURE, "[SANDBOX] Usage : %s <elf> [<arg1...>]", argv[0]);
  }

  if(strcmp(argv[1],"-c")!=0)
    
  {

    FILE *openfileincurrent;
  	openfileincurrent = fopen(".fendrc", "r") ;

  		

   if(openfileincurrent==NULL)
    {
     	FILE *openfileinhome;
      
      char *strhome = strcat(getenv("HOME"),".fendrc");
       openfileinhome= fopen(strhome,"r");
    	if(openfileinhome==NULL)
  		{
  			errx(EXIT_FAILURE, "Must provide config file");

  		}
  		else
  		{
  			config=strhome;
  			sandbox_initialization(&sb, argv+1,config);
  		}

  			
  	}
  	else
  	{
  		config=".fendrc";
  		sandbox_initialization(&sb, argv+1,config);
  	}

  }
  else
  {  config= argv[2];
  	sandbox_initialization(&sb, argv+3,config);
  	
  }



  for(;;) {
  sandbox_run(&sb,config);
  }



    return EXIT_SUCCESS;
  }


