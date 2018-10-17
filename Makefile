CC = g++
CFLAGS	+= -Wall -g 
LDFLAGS += -L /home/mengweibin/anaconda2/envs/python35/lib/ -lcrypto -lssl -lmysqlclient  -L /usr/lib/mysql/ -I/home/mengweibin/anaconda2/pkgs/openssl-1.0.2l-0/include/

#LDFLAGS += -lcrypto -lssl -lmysqlclient  -L/usr/lib/mysql/ 
vpath /home/mengweibin/anaconda2/pkgs/openssl-1.0.2l-0/include/openssl
.PHONY: clean

ssl_srv: ssl_srv.c packaging.c mysql_interface.c Sha256Calc.c dlist.c
	$(CC) $^ -o $@ $(LDFLAGS)

ssl_cli: ssl_cli.c packaging.c
	$(CC) $^ -o $@ $(LDFLAGS)

clean:
	rm -f `file * | grep ELF | cut -d: -f1`
	rm -f *~
