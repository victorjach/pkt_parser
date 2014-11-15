CC = gcc
CFLAGS = -g -std=c99 -Wall -Werror -D_GNU_SOURCE
TARGET = pktcap
SRCS = pktcap.c
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: $(OBJS) $(DEPS)
	$(CC) $(OBJS) -o $(TARGET)
%.o: %.c
	$(CC) -MM $(CFLAGS) -c $< > $*.d
	$(CC) $(CFLAGS) -c $< -o $@

-include $(OBJS:.o=.d)
	
.PHONY: clean
clean:
	rm -f *.o *.d $(TARGET)
