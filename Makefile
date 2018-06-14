SOURCEDIR:=$(CURDIR)

SOURCES = $(wildcard ${SOURCEDIR}/*.c)
OBJECTS = $(patsubst ${SOURCEDIR}/%.c, %.o, ${SOURCES})
LIB=libtrius.a

CC=gcc
LDFLAGS=-lprotobuf-c -lnanomsg
CFLAGS:=-g -O0


%.o: %.c
	$(CC) $(CLFAGS) $(LDFLAGS) -I. -c $< -o $@

lib: ${OBJECTS}
	ar -cr ${LIB} ${OBJECTS}

install: lib
	cp ${LIB} /usr/local/lib
