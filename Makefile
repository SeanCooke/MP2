#
# FILE:		Makefile
#
# PURPOSE:	Compile the program.
#

# Location of the BPF Assembler
BPFA = $(HOME)/src/bpfa/bpfa

# Compiler flags
CFLAGS	= -g -I.
LDFLAGS = -L.

all: webspy

webspy: webspy.o packet.o
	cc $(CFLAGS) -o webspy webspy.o packet.o $(LDFLAGS) -lpcap

webspy.o: webspy.c
	cc ${CFLAGS} -c webspy.c

packet.o: packet.c httpfilter.h
	cc ${CFLAGS} -c packet.c

httpfilter.h: http.bpf
	$(BPFA) $< > $@

#
# Maintainence Targets
#
clean:
	rm -f *.o *.core httpfilter.h

clobber: clean
	rm -f webspy
