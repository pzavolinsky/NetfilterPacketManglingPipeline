.PHONY: all clean

SRC:=$(wildcard src/*.cpp)

all: bin/main

%.o : %.cpp
	g++ -g -Wall -Wno-long-long -c $< -o $@

bin/main: $(SRC:.cpp=.o)
	mkdir -p bin
	g++ -g -Wall -pedantic $^ -o $@ -lnetfilter_queue
	@echo
	@echo "[DONE] sudo $@"
	@echo

clean:
	rm -rf bin src/*.o
