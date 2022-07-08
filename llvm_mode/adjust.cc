// 调整.ci.bc 和 .bc在BBID上的偏移


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>



int main()
{
  FILE* bc_file = fopen("bc_file.txt","w+");
  FILE* ci_bc_file = fopen("bbinfo-ci-bc.txt","r");
  char buf_bc[1024];
  char buf_ci_bc[1024];
  char temp[1024];
  if (bc_file==NULL || ci_bc_file==NULL){
    errs() << "bc_file.txt  or bbinfo-ci-bc.txt not exist\n";
    return;
    // FATAL("suffix.txt not exist");
  }

	std::cout << "adjust bbinfo..." << std::endl;
  
  //第一行存储后继基本块的总数
  if(fgets(buf_bc,sizeof(buf_bc),bc_file)!=NULL){
    if(fgets(buf_ci_bc,sizeof(buf_ci_bc),bc_file)!=NULL){
      if(!strcmp(buf_bc,buf_ci_bc)){
        memcpy(temp, buf_ci_bc, sizeof(buf_ci_bc));
        if(fgets(buf_ci_bc,sizeof(buf_ci_bc),bc_file)!=NULL){
          if(!strcmp(buf_bc,buf_ci_bc)){
            errs() << "something goes wrong!!!\n";

            exit(1);
          }
          // 说明只偏移了一位，可以调整


        }
      }
    }
  }


}