#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <unistd.h>
#include <termios.h>

typedef unsigned char BYTE;

/*
	This Library is written by Alexander Lange and intends to provide a simple API for AES related cryptography for files.
*/


int write_metadata96(FILE *fp, BYTE* watermark, BYTE algorithm, BYTE *leftover, BYTE * salt, BYTE * hash) {
	int expected_in = 0x00;
	
	expected_in += fwrite(watermark, 1, 30, fp);
	expected_in += fwrite(&algorithm, 1, 1, fp);
	expected_in += fwrite(leftover, 1, 1, fp);
	expected_in += fwrite(salt, 1, 32, fp);
	expected_in += fwrite(hash, 1, 32, fp);
	
	if(expected_in != 96) {
		return 1;
	}
	return 0;
}

int read_metadata96(FILE *fp, BYTE* watermark, BYTE *algorithm, BYTE *leftover, BYTE * salt, BYTE * hash) {
	int expected_in = 0x00;
	
	expected_in += fread(watermark, 1, 30, fp);
	expected_in += fread(algorithm, 1, 1, fp);
	expected_in += fread(leftover, 1, 1, fp);
	expected_in += fread(salt, 1, 32, fp);
	expected_in += fread(hash, 1, 32, fp);
	
	if(expected_in != 96) {
		return 1;
	}
	return 0;
}

int encrypt_data(FILE*in, FILE*out, unsigned int algorithm, BYTE operation, BYTE leftover, BYTE *key, BYTE* iv, unsigned int bs) {
	unsigned int expected_in;
	unsigned int expected_out;
	int initial_algorithm = 0;
	gcry_cipher_hd_t aes_instance;
	fseek(in, 0, SEEK_SET);
	fseek(out, 96, SEEK_SET);
	BYTE * buff_in = (BYTE*) malloc(bs);
	BYTE * buff_out = (BYTE*) malloc(bs);
	if(!buff_in || !buff_out) { return 2;}

	switch(algorithm) {
		case 0:
			initial_algorithm = 9; // rjindael
			break;
		case 1:
			initial_algorithm = 306; // serpent
			break;
		case 2:
			initial_algorithm = 312; // camillia
			break;
	}
	gcry_cipher_open (&aes_instance, initial_algorithm, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
	gcry_cipher_setkey (aes_instance, key, 32);
	gcry_cipher_setiv (aes_instance, iv, 16);
		
	while((expected_in = fread(buff_in, 1, bs, in)) > 0) {
		if(expected_in%16 != 0) {
			expected_out = expected_in+(16-(leftover%16));
			expected_in += (16-(leftover%16));
		}
		else {
			expected_out = expected_in;
		}
		gcry_cipher_encrypt (aes_instance, buff_out, expected_out, buff_in, expected_in);
		
		if(fwrite(buff_out, 1, expected_out, out) != expected_out) {
			return 3;
		}
	}
	gcry_cipher_close(aes_instance);
	return 0;
}

int decrypt_data(FILE*in, FILE*out, unsigned int algorithm, BYTE operation, BYTE leftover, BYTE* key, BYTE *iv, unsigned int bs) {
	unsigned int expected_in;
	unsigned int expected_out;
	int initial_algorithm = 0;
	unsigned int count = 0;
	gcry_cipher_hd_t aes_instance;
	fseek(in, 0, SEEK_END);
	double len = ftell(in) -96;
	fseek(in,96,SEEK_SET);
	fseek(out, 0, SEEK_SET);	
	BYTE * buff_in = (BYTE*) malloc(bs);
	BYTE * buff_out = (BYTE*) malloc(bs);
	unsigned int chunks = len/bs;
	if(!buff_in || !buff_out) { return 2;}
	
	switch(algorithm) {
		case 0:
			initial_algorithm = 9; // rjindael
			break;
		case 1:
			initial_algorithm = 306; // serpent
			break;
		case 2:
			initial_algorithm = 312; // camillia
			break;
	}
	gcry_cipher_open (&aes_instance, initial_algorithm, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
	gcry_cipher_setkey (aes_instance, key, 32);
	gcry_cipher_setiv (aes_instance, iv, 16);
		
	while((expected_in = fread(buff_in, 1, bs, in)) > 0) {
		expected_out = expected_in;
		count++;
		gcry_cipher_decrypt (aes_instance, buff_out, expected_out, buff_in, expected_in);
		
		
		if(count >= chunks) {
			expected_out = expected_in -((16-leftover)%16);
			
		}
		
		
		if(fwrite(buff_out, 1, expected_out, out) != expected_out) {
			return 3;
		}
	}
	gcry_cipher_close(aes_instance);
	return 0;


}

int password_veri(char* password) {
	char * verif_password = (char*) calloc(128, 1);
	struct termios term;
	tcgetattr(1, &term);
	term.c_lflag &= ~ECHO;
	tcsetattr(1, TCSANOW, &term);
	printf("Enter Password:\n");
	while (strlen(password) <5 || strlen(password) > 127 ){
		fgets(password, 128, stdin);
	}
	printf("Retype Password:\n");
	fgets(verif_password, 128, stdin);
	if (strcmp(verif_password, password) == 0) {
		term.c_lflag |= ECHO;
		tcsetattr(1, TCSANOW, &term);
		return 0;
	}
	term.c_lflag |= ECHO;
	tcsetattr(1, TCSANOW, &term);
	return 1;
}

int password_noveri(char* password) {
	struct termios term;
	tcgetattr(1, &term);
	term.c_lflag &= ~ECHO;
	tcsetattr(1, TCSANOW, &term);
	printf("Enter Password:\n");
	while (strlen(password) <5 || strlen(password) > 127 ){
		fgets(password, 128, stdin);
	}
	term.c_lflag |= ECHO;
	tcsetattr(1, TCSANOW, &term);
	return 0;
}



