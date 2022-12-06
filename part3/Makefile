# the compiler: gcc for C program, define as g++ for C++
CC = gcc
# compiler flags
CFLAGS = -shared
# the lib to build:
LIB = hook
# binary to exploit
BINARY = hello_world
RM = rm

all: $(TARGET)

$(LIB): $(LIB).c
	$(CC) $(CFLAGS) -o lib$(LIB).so $(LIB).c

hack: $(LIB).c $(BINARY)
	LD_PRELOAD=$(shell pwd)/lib$(LIB).so ./$(BINARY)

clean:
	$(RM) $(TARGET)