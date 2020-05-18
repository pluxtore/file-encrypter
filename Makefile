CC=gcc
LIBGCRYPT= `libgcrypt-config --libs`

norcais: lib/libnorc.c main.c
	$(CC) -c  -o lib/libnorc.o lib/libnorc.c $(LIBGCRYPT)
	$(CC) -o norcais main.c lib/libnorc.o $(LIBGCRYPT)

