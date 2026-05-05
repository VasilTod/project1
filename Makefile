LIBS=-lssl -lcrypto -lpthread
all:
	gcc client.c crypto.c -o client $(LIBS)
	gcc server.c -o server $(LIBS)