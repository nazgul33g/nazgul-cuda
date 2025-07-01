#---------------------------------------------------------------------
# Makefile for KeyHunt
#
# Author : Jean-Luc PONS
# Adaptado para Ubuntu + CUDA 12.8

SRC = Base58.cpp IntGroup.cpp Main.cpp Bloom.cpp Random.cpp \
      Timer.cpp Int.cpp IntMod.cpp Point.cpp SECP256K1.cpp \
      KeyHunt.cpp GPU/GPUGenerate.cpp hash/ripemd160.cpp \
      hash/sha256.cpp hash/sha512.cpp hash/ripemd160_sse.cpp \
      hash/sha256_sse.cpp hash/keccak160.cpp GmpUtil.cpp CmdParse.cpp

OBJDIR = obj

OBJET = $(addprefix $(OBJDIR)/, $(SRC:.cpp=.o) GPU/GPUEngine.o)

CXX        = g++9
CUDA       = /usr/local/cuda-12.8
CXXCUDA    = $(CUDA)/bin/nvcc
NVCC       = $(CUDA)/bin/nvcc
ccap       = $(shell echo $(CCAP) | tr -d '.')

CXXFLAGS   = -DWITHGPU -m64 -mssse3 -Wno-write-strings -O2 -I. -I$(CUDA)/include
NVCCFLAGS  = -maxrregcount=0 --ptxas-options=-v --compile --compiler-options -fPIC \
             -ccbin $(CXX) -m64 -O2 -I$(CUDA)/include -gencode=arch=compute_$(ccap),code=sm_$(ccap)

LFLAGS     = -lgmp -lpthread -L$(CUDA)/lib64 -lcudart -lcuda

#--------------------------------------------------------------------

all: KeyHunt

KeyHunt: $(OBJET)
	$(CXX) $(OBJET) $(LFLAGS) -o KeyHunt

$(OBJDIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJDIR)/GPU/GPUEngine.o: GPU/GPUEngine.cu
	@mkdir -p $(dir $@)
	$(NVCC) $(NVCCFLAGS) -o $@ -c $<

clean:
	@echo Cleaning...
	@rm -f $(OBJDIR)/*.o
	@rm -f $(OBJDIR)/GPU/*.o
	@rm -f $(OBJDIR)/hash/*.o
	@rm -f KeyHunt

