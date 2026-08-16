CC        = clang
CXX       = clang++
CFLAGS    = -O2 -g -Wall -Wextra
CXXFLAGS  = -O2 -g -Wall -Wextra -std=c++20
BPF_CFLAGS = -O2 -g -Wall -Wextra -target bpf
LDLIBS    = -lbpf -lelf -lz

all: fw_prog.o falconwall

fw_prog.o: fw_prog.c
	$(CC) $(BPF_CFLAGS) -c $< -o $@

falconwall: fw.cpp detector.cpp detector.hpp
	$(CXX) $(CXXFLAGS) fw.cpp detector.cpp -o $@ $(LDLIBS)

clean:
	rm -f falconwall fw_prog.o

.PHONY: all clean
