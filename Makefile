all: nsclient

clean:
	rm -f ./nsclient


nsclient: nsclient.c
	gcc -o nsclient nsclient.c