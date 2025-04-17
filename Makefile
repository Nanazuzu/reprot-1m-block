#Makefile
all: nfqnl_test

nfqnl_test: nfqnl_test.o
	g++ -o nfqnl_test nfqnl_test.o -lnetfilter_queue `pkg-config --cflags --libs glib-2.0`

nfqnl_test.o: nfqnl_test.c
	g++ -c -o nfqnl_test.o nfqnl_test.c -lnetfilter_queue `pkg-config --cflags --libs glib-2.0`

clean:
	rm -f nfqnl_test
	rm -f *.o
