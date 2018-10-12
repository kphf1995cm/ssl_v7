CC = g++
CFLAGS	+= -Wall -g 
LDFLAGS += -lcrypto -lssl -lmysqlclient  -L /usr/lib/mysql/

.PHONY: clean

ssl_srv: ssl_srv.c packaging.c mysql_interface.c Sha256Calc.c dlist.c
	$(CC) $^ -o $@ $(LDFLAGS)

ssl_cli: ssl_cli.c packaging.c
	$(CC) $^ -o $@ $(LDFLAGS)

clean:
	rm -f `file * | grep ELF | cut -d: -f1`
	rm -f *~
