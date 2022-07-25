/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <list>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <set>
#include <map>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/CFGPrinter.h"

#if defined(LLVM34)
#include "llvm/DebugInfo.h"
#else
#include "llvm/IR/DebugInfo.h"
#endif

#if defined(LLVM34) || defined(LLVM35) || defined(LLVM36)
#define LLVM_OLD_DEBUG_API
#endif

using namespace llvm;
using namespace std;

std::map<BasicBlock*,std::set<BasicBlock*>> target_suffix;
std::set<BasicBlock*> all_suffix;
std::set<BasicBlock*> all_target;
std::set<BasicBlock*> nonreachable;
u32 total_suffix_num;

std::map<uint32_t, BasicBlock *> ID2BB;
std::map< BasicBlock *,uint32_t> BB2ID;



cl::opt<std::string> DistanceFile(
    "distance",
    cl::desc("Distance file containing the distance of each basic block to the provided targets."),
    cl::value_desc("filename")
);

cl::opt<std::string> TargetsFile(
    "targets",
    cl::desc("Input file containing the target lines of code."),
    cl::value_desc("targets"));

cl::opt<std::string> OutDirectory(
    "outdir",
    cl::desc("Output directory where Ftargets.txt, Fnames.txt, and BBnames.txt are generated."),
    cl::value_desc("outdir"));

namespace llvm {

template<>
struct DOTGraphTraits<Function*> : public DefaultDOTGraphTraits {//重写了DOTGraphTraints代码，修改node的内容，这个部分的代码是在LLVM画图的时候会调用的
  DOTGraphTraits(bool isSimple=true) : DefaultDOTGraphTraits(isSimple) {}

  static std::string getGraphName(Function *F) {
    return "CFG for '" + F->getName().str() + "' function";
  }

  std::string getNodeLabel(BasicBlock *Node, Function *Graph) {
    if (!Node->getName().empty()) {
      return Node->getName().str();
    }

    std::string Str;
    raw_string_ostream OS(Str);

    Node->printAsOperand(OS, false);
    return OS.str();
  }

//重写某个函数内容，使得在构建function级别CFG的时候，查询CG。构建全局CFG





};

} // namespace llvm

namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

      // StringRef getPassName() const override {
      //  return "American Fuzzy Lop Instrumentation";
      // }

  };

}

Module* M2;
char AFLCoverage::ID = 0;

static void getDebugLoc(const Instruction *I, std::string &Filename,
                        unsigned &Line) {
#ifdef LLVM_OLD_DEBUG_API
  DebugLoc Loc = I->getDebugLoc();
  if (!Loc.isUnknown()) {
    DILocation cDILoc(Loc.getAsMDNode(M.getContext()));
    DILocation oDILoc = cDILoc.getOrigLocation();

    Line = oDILoc.getLineNumber();
    Filename = oDILoc.getFilename().str();

    if (filename.empty()) {
      Line = cDILoc.getLineNumber();
      Filename = cDILoc.getFilename().str();
    }
  }
#else
  if (DILocation *Loc = I->getDebugLoc()) {
    Line = Loc->getLine();
    Filename = Loc->getFilename().str();

    if (Filename.empty()) {
      DILocation *oDILoc = Loc->getInlinedAt();
      if (oDILoc) {
        Line = oDILoc->getLine();
        Filename = oDILoc->getFilename().str();
      }
    }
  }
#endif /* LLVM_OLD_DEBUG_API */
}

static bool isBlacklisted(const Function *F) {
  static const SmallVector<std::string, 8> Blacklist = {
    "asan.",
    "llvm.",
    "sancov.",
    "__ubsan_handle_",
    "free",
    "malloc",
    "calloc",
    "realloc"
  };

  for (auto const &BlacklistFunc : Blacklist) {
    if (F->getName().startswith(BlacklistFunc)) {
      return true;
    }
  }

  return false;
}

void readTarget(){
  std::string out_dir = OutDirectory;
  out_dir += "/targets_id.txt";
  FILE* target_file = fopen(out_dir.c_str(),"r");
  char buf[1024];
  if (target_file==NULL){
    errs() <<out_dir<< "target_id.txt not exist\n";
    return;
    // FATAL("target_file.txt not exist");
  }

	std::cout << "loading target_file..." << std::endl;

  int target_bbid = 0;
  while(fgets(buf,sizeof(buf),target_file)!=NULL){
    char *token;
    token = strtok(buf," ");    
    target_bbid = atoi(token);
    all_target.insert(ID2BB[target_bbid]);
  }


  fclose(target_file);
  
}

void readSuffix() {
  std::string out_dir = OutDirectory;
  out_dir += "/suffix.txt";
  FILE* suffix_file = fopen(out_dir.c_str(),"r");
  char buf[1024];
  if (suffix_file==NULL){
    errs() <<out_dir<< "suffix.txt not exist\n";
    return;
    // FATAL("suffix.txt not exist");
  }

	std::cout << "loading suffix..." << std::endl;
  
  //第一行存储后继基本块的总数
  if(fgets(buf,sizeof(buf),suffix_file)!=NULL){
    char *token;
    token = strtok(buf," ");    
    total_suffix_num = atoi(token);
  }
  std::cout << "total_suffix_num: "<<total_suffix_num << std::endl;

  // std::set<BasicBlock *> temp_suffix;
  int target_id=0;
  while(fgets(buf, sizeof(buf), suffix_file) != NULL) {
    char* token;
    token = strtok(buf, " ");
    int temp_target_id = atoi(token);
    token = strtok(NULL, " ");
    int suffix_id = atoi(token);
    // errs() << "first: " << temp_target_id << " suffix: " << suffix_id << "\n";
    // if (temp_target_id != target_id)
    // {
      // target_suffix[ID2BB[target_id]] = temp_suffix;
      // temp_suffix.clear();
    //   target_id = temp_target_id;
    // }

    // temp_suffix.insert(ID2BB[suffix_id]);
    all_suffix.insert(ID2BB[suffix_id]);
	}
  fclose(suffix_file);

}

void readNonreachable() {
  FILE* nonreachable_file = fopen("nonreachable.txt","r");
  char buf[1024];
  if (nonreachable_file==NULL){
    errs() << "nonreachable.txt not exist\n";
    return;
    // FATAL("suffix.txt not exist");
  }

	std::cout << "loading nonreachable..." << std::endl;
  int num = 0;

  std::set<BasicBlock *> temp_suffix;
  while(fgets(buf, sizeof(buf), nonreachable_file) != NULL) {
    char* token;
    token = strtok(buf, " ");
    int nonID = atoi(token);
    // errs() << "first: " << nonID << "\n";
    nonreachable.insert(ID2BB[nonID]);
    num++;
  }
  fclose(nonreachable_file);
  errs() << "nonreachable num: " << num << "\n";
}


void setBBID(Module &M){
  uint32_t bb_id = 0;
  uint32_t line = 0;

  FILE *bc_file = fopen("bbinfo-bc.txt", "r");
  FILE *bc_file_next = fopen("bbinfo-bc.txt", "r");
  FILE *ci_bc_file = fopen("bbinfo-ci-bc.txt", "r");
  FILE *ci_bc_file_next = fopen("bbinfo-ci-bc.txt", "r");
  char buf_bc[1024];
  char buf_bc_next[1024];
  char buf_ci_bc[1024];
  char buf_ci_bc_next[1024];
  char temp[1024];
  if (bc_file == NULL || ci_bc_file == NULL || bc_file_next ==NULL || ci_bc_file==NULL)
  {
    // errs() << "bbinfo-bc.txt  or bbinfo-ci-bc.txt not exist\n";
    // return;
    FATAL("bbinfo-bc.txt  or bbinfo-ci-bc.txt not exist\n");
  }
  if(!fgets(buf_bc_next,sizeof(buf_bc_next),bc_file_next)!=NULL){
    FATAL("bbinfo-bc.txt  or bbinfo-ci-bc.txt cannot read next\n");
  }
  if( !fgets(buf_ci_bc_next,sizeof(buf_ci_bc_next),ci_bc_file_next)!=NULL){
    FATAL("bbinfo-bc.txt  or bbinfo-ci-bc.txt cannot read next\n");
  }
  std::cout << "adjust bbinfo..." << std::endl;
  uint32_t is_external = 0;

  for (auto &F : M)
  {
    for(auto &BB:F){
      is_external = 0;
      for (auto &I : BB) {
        
        std::string filename;
        unsigned line_1;

        getDebugLoc(&I, filename, line_1);
        
          /* Don't worry about external libs */
          static const std::string Xlibs("/usr/");
          if (filename.empty() || line_1 == 0)
            continue;
          if (!filename.compare(0, Xlibs.size(), Xlibs)){
            is_external = 1;
          }

      }
      if(is_external == 1){
        continue;
      }
      char null_bbinfo[10] = "{ }";


      // 这个对齐方式在某些程序中仍然存在问题
      {
        if(fgets(buf_bc_next,sizeof(buf_bc_next),bc_file_next)!=NULL && fgets(buf_bc,sizeof(buf_bc),bc_file)!=NULL){
          while(fgets(buf_ci_bc_next,sizeof(buf_ci_bc_next),ci_bc_file_next)!=NULL && fgets(buf_ci_bc,sizeof(buf_ci_bc),ci_bc_file)!=NULL  ){
            // errs() << bb_id << " 22 bbinfo: " << buf_bc<< buf_bc_next  << "  " << buf_ci_bc << buf_ci_bc_next << "\n";
            // 如果两个值不相等，需要调整
            // errs() << bb_id<<" bbinfo: "<<buf_bc<<"  "<<buf_ci_bc << "\n";
            if (strcmp(buf_bc, buf_ci_bc)){
              // 如果ci.bc中出现了"{ }""
              if(strstr(buf_ci_bc,null_bbinfo)){
                // case2: bc和ci.bc的下一行一样
                if(!strcmp(buf_bc,buf_ci_bc_next)){
                  fgets(buf_ci_bc, sizeof(buf_ci_bc), ci_bc_file);
                  fgets(buf_ci_bc_next, sizeof(buf_ci_bc_next), ci_bc_file_next);
            // errs() << bb_id << " 33 bbinfo: " << buf_bc<< buf_bc_next  << "  " << buf_ci_bc << buf_ci_bc_next << "\n";

                  bb_id++;
                  break;
                }
                // case1: bc的下一行和ci.bc的下一行一样
                else if(!strcmp(buf_bc_next,buf_ci_bc_next)){
                  break;
                }
                // case3: bc和ci.bc的下一行不一样，但ci.bc的下一行是"{ }"
                else if(strstr(buf_ci_bc_next,null_bbinfo)){
                  bb_id++;
                  continue;
                }
                // case4: bc和ci.bc的下一行不一样，且ci.bc的下一行不是"{ }" ERROR
                else{
                  errs() << bb_id << " 11 bbinfo: " << buf_bc<< buf_bc_next  << "  " << buf_ci_bc << buf_ci_bc_next << "\n";
                  FATAL("something goes wrong!!!\n");
                }
              }else{
                errs() << bb_id << " bbinfo: " << buf_bc << "  " << buf_ci_bc << "\n";
                FATAL("something goes wrong!!!\n");
              }
            }
            break;
          }
        }
      }

      ID2BB[bb_id] = &BB;
      BB2ID[&BB] = bb_id;
      bb_id++;
    }
  }
  fclose(bc_file);
  fclose(ci_bc_file);
  fclose(bc_file_next);
  fclose(ci_bc_file_next);
  errs() << "total bb_id: " << bb_id << "\n";

  readSuffix();
  readNonreachable();
  readTarget();
}

bool AFLCoverage::runOnModule(Module &M) {
  M2 = &M;

  bool is_aflgo = false;
  bool is_aflgo_preprocessing = false;

  if (!TargetsFile.empty() && !DistanceFile.empty()) {
    FATAL("Cannot specify both '-targets' and '-distance'!");
    return false;
  }

  std::list<std::string> targets;
  std::map<std::string, int> bb_to_dis;
  std::vector<std::string> basic_blocks;

  if (!TargetsFile.empty()) {

    if (OutDirectory.empty()) {
      FATAL("Provide output directory '-outdir <directory>'");
      return false;
    }

    std::ifstream targetsfile(TargetsFile);
    std::string line;
    while (std::getline(targetsfile, line))
      targets.push_back(line);
    targetsfile.close();

    is_aflgo_preprocessing = true;

  } else if (!DistanceFile.empty()) {

    std::ifstream cf(DistanceFile);
    if (cf.is_open()) {

      std::string line;
      while (getline(cf, line)) {

        std::size_t pos = line.find(",");
        std::string bb_name = line.substr(0, pos);
        int bb_dis = (int) (100.0 * atof(line.substr(pos + 1, line.length()).c_str()));

        bb_to_dis.emplace(bb_name, bb_dis);
        basic_blocks.push_back(bb_name);

      }
      cf.close();

      is_aflgo = true;

    } else {
      FATAL("Unable to find %s.", DistanceFile.c_str());
      return false;
    }

  }

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    if (is_aflgo || is_aflgo_preprocessing)
      SAYF(cCYA "aflgo-llvm-pass (yeah!) " cBRI VERSION cRST " (%s mode)\n",
           (is_aflgo_preprocessing ? "preprocessing" : "distance instrumentation"));
    else
      SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");


  } else be_quiet = 1;

  /* Decide instrumentation ratio */

  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Default: Not selective */
  char* is_selective_str = getenv("AFLGO_SELECTIVE");
  unsigned int is_selective = 0;

  if (is_selective_str && sscanf(is_selective_str, "%u", &is_selective) != 1)
    FATAL("Bad value of AFLGO_SELECTIVE (must be 0 or 1)");

  char* dinst_ratio_str = getenv("AFLGO_INST_RATIO");
  unsigned int dinst_ratio = 100;

  if (dinst_ratio_str) {

    if (sscanf(dinst_ratio_str, "%u", &dinst_ratio) != 1 || !dinst_ratio ||
        dinst_ratio > 100)
      FATAL("Bad value of AFLGO_INST_RATIO (must be between 1 and 100)");

  }

  /* Instrument all the things! */

  int inst_blocks = 0;

  if (is_aflgo_preprocessing) {

    std::ofstream bbnames(OutDirectory + "/BBnames.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream bbcalls(OutDirectory + "/BBcalls.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream fnames(OutDirectory + "/Fnames.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream ftargets(OutDirectory + "/Ftargets.txt", std::ofstream::out | std::ofstream::app);

    /* Create dot-files directory */
    std::string dotfiles(OutDirectory + "/dot-files");
    if (sys::fs::create_directory(dotfiles)) {
      FATAL("Could not create directory %s.", dotfiles.c_str());
    }

    for (auto &F : M) {//我应该在这里添加一些代码，使得在遍历FinM的时候可以对functioncall做关联

      bool has_BBs = false;
      std::string funcName = F.getName().str();

      /* Black list of function names */
      if (isBlacklisted(&F)) {
        continue;
      }

      bool is_target = false;
      for (auto &BB : F) {

        std::string bb_name("");
        std::string filename;
        unsigned line;

        for (auto &I : BB) { //对基本块中的每条指令进行处理；#可以区分指令是否是call指令？
          //bool iscallsite = llvm::isa<CallInst>(I); 在下面实现了

          getDebugLoc(&I, filename, line);

          /* Don't worry about external libs */
          static const std::string Xlibs("/usr/");
          if (filename.empty() || line == 0 || !filename.compare(0, Xlibs.size(), Xlibs))
            continue;

          if (bb_name.empty()) {

            std::size_t found = filename.find_last_of("/\\");
            if (found != std::string::npos)
              filename = filename.substr(found + 1);

            bb_name = filename + ":" + std::to_string(line);//为每个基本块使用文件名:行数的方法命名了
          }

          if (!is_target) {
              for (auto &target : targets) {
                std::size_t found = target.find_last_of("/\\");
                if (found != std::string::npos)
                  target = target.substr(found + 1);

                std::size_t pos = target.find_last_of(":");
                std::string target_file = target.substr(0, pos);
                unsigned int target_line = atoi(target.substr(pos + 1).c_str());

                if (!target_file.compare(filename) && target_line == line) //比较当前指令是否是target
                  is_target = true;

              }
            }

            if (auto *c = dyn_cast<CallInst>(&I)) {//动态转换，判断I是否是callinst

              std::size_t found = filename.find_last_of("/\\");
              if (found != std::string::npos)
                filename = filename.substr(found + 1);

              if (auto *CalledF = c->getCalledFunction()) {//得到调用函数的文件位置，被调用的函数
                if (!isBlacklisted(CalledF)){
                  bbcalls << bb_name << "," << CalledF->getName().str() << "\n";

                  //添加一条边，从当前I所在的BB指向CalledF的第一个BB
                  

                  
                  }
              }
            }
        }

        if (!bb_name.empty()) {

          BB.setName(bb_name + ":");
          /*xy
          */
          if (!BB.hasName()) {
            std::string newname = bb_name + ":";
            Twine t(newname);
            SmallString<256> NameData;
            StringRef NameRef = t.toStringRef(NameData);
            MallocAllocator Allocator;
            BB.setValueName(ValueName::Create(NameRef, Allocator));
          }

          bbnames << BB.getName().str() << "\n";
          has_BBs = true;

#ifdef AFLGO_TRACING
          auto *TI = BB.getTerminator();
          IRBuilder<> Builder(TI);

          Value *bbnameVal = Builder.CreateGlobalStringPtr(bb_name);
          Type *Args[] = {
              Type::getInt8PtrTy(M.getContext()) //uint8_t* bb_name
          };
          FunctionType *FTy = FunctionType::get(Type::getVoidTy(M.getContext()), Args, false);
          Constant *instrumented = M.getOrInsertFunction("llvm_profiling_call", FTy);
          Builder.CreateCall(instrumented, {bbnameVal});
#endif

        }
      }

      if (has_BBs) {
        /* Print CFG */
        std::string cfgFileName = dotfiles + "/cfg." + funcName + ".dot";
        std::error_code EC;
        raw_fd_ostream cfgFile(cfgFileName, EC, sys::fs::OF_None);
        if (!EC) {
          WriteGraph(cfgFile, &F, true); //不再对function级画Intraprocedure控制流图
        }

        /*
        std::string cfg_file_name2 = dotfiles + "/cfg_file_name." + funcName + ".dot";
        std::error_code EC2;
        raw_fd_ostream cfgFile2(cfg_file_name2, EC2, sys::fs::F_None);
        if (!EC2) {
          WriteGraph(cfgFile2, &F, true); 
        }
        */

        if (is_target)
          ftargets << F.getName().str() << "\n";
        fnames << F.getName().str() << "\n";
      }

    //在每一个function级构建边？
    //构建ICFG

    }

  } else {
    /* Distance instrumentation */

    LLVMContext &C = M.getContext();
    IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

#ifdef __x86_64__
    IntegerType *LargestType = Int64Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 8);
    ConstantInt *MapTargetLoc = ConstantInt::get(LargestType, MAP_SIZE + 24);
#else
    IntegerType *LargestType = Int32Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 4);
#endif
    ConstantInt *MapDistLoc = ConstantInt::get(LargestType, MAP_SIZE);
    ConstantInt *One = ConstantInt::get(LargestType, 1);

    /* Get globals for the SHM region and the previous location. Note that
       __afl_prev_loc is thread-local. */

    GlobalVariable *AFLMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");


  GlobalVariable *AFLMapPtrSuf = (GlobalVariable*)M.getOrInsertGlobal("__afl_area_ptr_suf",PointerType::get(Int8Ty, 0),[]() -> GlobalVariable* {
      return new GlobalVariable(*M2, PointerType::get(IntegerType::getInt8Ty(M2->getContext()), 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr_suf");
  });

  GlobalVariable *AFLMapPtrSufBB = (GlobalVariable*)M.getOrInsertGlobal("__afl_area_ptr_suf_bb",PointerType::get(Int8Ty, 0),[]() -> GlobalVariable* {
      return new GlobalVariable(*M2, PointerType::get(IntegerType::getInt8Ty(M2->getContext()), 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr_suf_bb");
    });

    GlobalVariable *AFLPrevLoc = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
        0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

    setBBID(M);
    uint32_t suf_bb_id = 0;

    for (auto &F : M) {

      int distance = -1;

      for (auto &BB : F) {

        distance = -1;

        if (is_aflgo) {

          std::string bb_name;
          for (auto &I : BB) {
            std::string filename;
            unsigned line;
            getDebugLoc(&I, filename, line);

            if (filename.empty() || line == 0)
              continue;
            std::size_t found = filename.find_last_of("/\\");
            if (found != std::string::npos)
              filename = filename.substr(found + 1);

            bb_name = filename + ":" + std::to_string(line);
            break;
          }

          if (!bb_name.empty()) {

            if (find(basic_blocks.begin(), basic_blocks.end(), bb_name) == basic_blocks.end()) {

              if (is_selective)
                continue;

            } else {

              /* Find distance for BB */

              if (AFL_R(100) < dinst_ratio) {
                std::map<std::string,int>::iterator it;
                for (it = bb_to_dis.begin(); it != bb_to_dis.end(); ++it)
                  if (it->first.compare(bb_name) == 0)
                    distance = it->second;

              }
            }
          }
        }

        BasicBlock::iterator IP = BB.getFirstInsertionPt();
        IRBuilder<> IRB(&(*IP));

        if (AFL_R(100) >= inst_ratio) continue;

        /* Make up cur_loc */

        unsigned int cur_loc = AFL_R(MAP_SIZE);

        ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

        /* Load prev_loc */

        LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
        PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

        /* Load SHM pointer */

        LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *MapPtrIdx =
            IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

        /* Update bitmap */

        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
        IRB.CreateStore(Incr, MapPtrIdx)
           ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        
        //对后继进行插桩
        if(all_suffix.find(&BB)!=all_suffix.end()){
          /* Load SHM pointer */

          LoadInst *MapPtrSuf = IRB.CreateLoad(AFLMapPtrSuf);
          MapPtrSuf->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
          Value *MapPtrIdxSuf =
              IRB.CreateGEP(MapPtrSuf, IRB.CreateXor(PrevLocCasted, CurLoc));

          /* Update bitmap */

          LoadInst *Counter = IRB.CreateLoad(MapPtrIdxSuf);
          Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
          Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
          IRB.CreateStore(Incr, MapPtrIdxSuf)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          // 对后继的基本块进行插桩
          
          llvm::LoadInst *MapPtrSufBB = IRB.CreateLoad(AFLMapPtrSufBB);
          // ConstantInt *cur_id = llvm::ConstantInt::get(IntegerType::getInt32Ty(*C), bb_id);
          // ConstantInt *cur_id = llvm::ConstantInt::get(IntegerType::getInt32Ty(C), BB2ID[&BB]);
          ConstantInt *cur_id = llvm::ConstantInt::get(IntegerType::getInt32Ty(C), suf_bb_id);

          llvm::Value *MapPtrIdxSufBB = IRB.CreateGEP(MapPtrSufBB, cur_id);
          llvm::LoadInst *CounterBB = IRB.CreateLoad(MapPtrIdxSufBB);
          llvm::Value *IncrBB = IRB.CreateAdd(CounterBB, ConstantInt::get(Int8Ty, 1));
          IRB.CreateStore(IncrBB, MapPtrIdxSufBB)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
          suf_bb_id++;
          // errs() << suf_bb_id << "\n";
        }

        /* Set prev_loc to cur_loc >> 1 */

        StoreInst *Store =
            IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        if (distance >= 0) {
          // errs() << distance << "\n";

          ConstantInt *Distance =
              ConstantInt::get(LargestType, (unsigned) distance);

          /* Add distance to shm[MAPSIZE] */

          Value *MapDistPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, MapDistLoc), LargestType->getPointerTo());
          LoadInst *MapDist = IRB.CreateLoad(MapDistPtr);
          MapDist->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          Value *IncrDist = IRB.CreateAdd(MapDist, Distance);
          IRB.CreateStore(IncrDist, MapDistPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          /* Increase count at shm[MAPSIZE + (4 or 8)] */

          Value *MapCntPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, MapCntLoc), LargestType->getPointerTo());
          LoadInst *MapCnt = IRB.CreateLoad(MapCntPtr);
          MapCnt->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          Value *IncrCnt = IRB.CreateAdd(MapCnt, One);
          IRB.CreateStore(IncrCnt, MapCntPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        }

        //标记target有无被触发
          // 在有些commit中，AFLGO对一些target没有计算距离，从而不能标记target
				if (all_target.find(&BB) != all_target.end()) {
          errs() << "target !\n";
          //写共享内存MapTargetLoc
          Value *MapTargetPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, MapTargetLoc), LargestType->getPointerTo());
          LoadInst *MapCnt = IRB.CreateLoad(MapTargetPtr);
          MapCnt->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          Value *IncrCnt = IRB.CreateAdd(MapCnt, One);
          IRB.CreateStore(IncrCnt, MapTargetPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
				}


        inst_blocks++;

      }
    }
    errs() << "suf_bb_id: " << suf_bb_id << "\n";
  }

  /* Say something nice. */

  if (!is_aflgo_preprocessing && !be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%, dist. ratio %u%%).",
             inst_blocks,
             getenv("AFL_HARDEN")
             ? "hardened"
             : ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN"))
               ? "ASAN/MSAN" : "non-hardened"),
             inst_ratio, dinst_ratio);

  }

  return true;

}


static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}


static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_ModuleOptimizerEarly, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
