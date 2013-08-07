PROG   = www6to4
RM     = rm -f
#CFLAGS  = -ggdb -Wall
#CFLAGS  = -g -DDMALLOC
#LDFLAGS = -L/usr/pkg/lib -ldmalloc

OBJS = www6to4.o parsers.c loaders.o socket.o

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $(PROG) $(OBJS) $(LDFLAGS)

.c.o:   $(PROG).h
	$(CC)  $(CFLAGS) -c $<

clean:
	$(RM) a.out core *.o *.obj $(PROG)

# $Id: Makefile,v 1.14 2001/12/12 14:45:24 dillema Exp $
# Author: F.W. Dillema
# Copyright 2001 F.W. Dillema,
# University of Tromso, Norway.
