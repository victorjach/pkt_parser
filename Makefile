CC=gcc
CFLAGS= -g -std=c99 -Wall -Werror -D_GNU_SOURCE
TARGET=pktcap
OBJS=pktcap.o

.PHONY: all
all: $(OBJS)
	$(CC) $(OBJS) -o $(TARGET)
$(OBJS): %.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@
	
.PHONY: clean
clean:
	rm -f *.o $(TARGET)
