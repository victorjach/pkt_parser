CC = gcc
CFLAGS = -g -std=c99 -Wall -Werror 
TARGET = libpkt.a
SRCS = pktlib.c protocol.c

OBJS = $(SRCS:.c=.o)

.PHONY: all
all: $(OBJS)
	$(AR) rcs $(TARGET) $(OBJS)

%.o: %.c
	$(CC) -MM $(CFLAGS) -c $< > $*.d
	$(CC) $(CFLAGS) -c $< -o $@

-include $(OBJS:.o=.d)
	
.PHONY: clean
clean:
	rm -f *.o *.d $(TARGET)


