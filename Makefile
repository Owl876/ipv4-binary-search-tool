CC=gcc
CFLAGS=-Wall -Wextra -Werror -O3 -fPIC
LDFLAGS=-ldl

EXEC=lab12dadN3251
SRCS=lab12dadN3251.c

PLUGINS=libdadN3251.so
PLUGIN_SRCS=libdadN3251.c

OBJS=$(SRCS:.c=.o)
PLUGIN_OBJS=$(PLUGIN_SRCS:.c=.o)

$(EXEC): $(OBJS) $(PLUGINS)
	$(CC) $(CFLAGS) -o $(EXEC) $(OBJS) $(LDFLAGS)

$(PLUGINS): $(PLUGIN_OBJS)
	$(CC) $(CFLAGS) -shared -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(PLUGIN_OBJS) $(EXEC) $(PLUGINS)

.PHONY: all clean
