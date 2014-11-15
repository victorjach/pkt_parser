CC = gcc
CFLAGS = -g -std=c99 -Wall -Werror -D_GNU_SOURCE
TARGET = pktcap
SRCS = pktcap.c
OBJS = $(SRCS:.c=.o)
PKTLIBDIR = pktlib

.PHONY: all
all: $(OBJS)
	$(MAKE) -C $(PKTLIBDIR)
	$(CC) -static -L$(PKTLIBDIR)  $(OBJS) -o $(TARGET) -lpkt 
%.o: %.c
	$(CC) -MM $(CFLAGS) -I$(PKTLIBDIR) -c $< > $*.d
	$(CC) $(CFLAGS) -I$(PKTLIBDIR) -c $< -o $@

-include $(OBJS:.o=.d)
	
.PHONY: clean
clean:
	rm -f *.o *.d $(TARGET)
	$(MAKE) -C $(PKTLIBDIR) clean


