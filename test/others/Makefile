CRIU_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)

loop:
	gcc -Wall loop.c -o loop

handle_error: handle_error.c
	$(CC) -Wall -Wextra -I$(CRIU_ROOT)/include -I$(CRIU_ROOT)/criu/include -I$(CRIU_ROOT)/criu/arch/x86/include handle_error.c -o handle_error
