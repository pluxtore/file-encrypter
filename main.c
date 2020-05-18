#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <gcrypt.h>
#include "include/norc.h"

typedef unsigned char BYTE;

struct ARG {
	char * infile;
	char * outfile;
	BYTE operation;
	unsigned int algorithm;
	BYTE remove_ifile_flag;
	BYTE help_flag;
	BYTE headless_flag;
	BYTE overwrite_flag;
	FILE * in;
	FILE * out;
	char * password;
} argument;


void show_help(char**argv) {
	printf("Usage : %s [args] [flags]\n", argv[0]);
	printf("\nAvailable arguments:\n");
	printf("  -i [filename]                     Specifies Infile.\n");
	printf("  -o [filename]                     Specifies Outfile.\n");
	printf("  -m [encrypt|decrypt|idle]         Work mode. \n");
	printf("  -a [rjindael|serpent|camillia]    Algorithm. \n");
	printf("  -b [blocksize]                    Blocksize. \n");
	printf("\nAvailable flags:\n");
	printf("  -h                                Shows this.\n");
	printf("  -r                                Flag that removes the Infile after operation.\n");
	printf("  -H                                Toggles headless mode. This is not recommended.\n");
	printf("  -w                                Flag to overwrite Outfile if it already exists.\n");
}


	
int main(int argc, char **argv) {
	argument.infile = (char *) calloc(256, 1);
	argument.outfile = (char *) calloc(256, 1);
	argument.password = (char*) calloc(128,1 );
	argument.operation = 3;
	argument.algorithm = 0;
	argument.remove_ifile_flag = 0;
	argument.headless_flag = 0;
	argument.help_flag = 0;
	argument.overwrite_flag = 0;
	
	int c, i;
	int check = 0;
	unsigned int bs = 16;
	
	
	
	
	while ((c= getopt(argc, argv, "i:o:m:a:b:rHhw")) != -1) {
		switch(c) {
			case 'i':
				argument.infile = optarg;
				check++;
				break;
			case 'o':
				argument.outfile = optarg;
				check++;
				break;
			case 'm':
				if (strcmp(optarg, "encrypt") == 0) {
					argument.operation = 1;
				}
				if (strcmp(optarg, "decrypt") == 0) {
					argument.operation = 2;
				}
				if (strcmp(optarg, "idle") == 0) {
					argument.operation = 0;
				}
				check++;
				break;
			case 'a':
				if (strcmp(optarg, "rjindael") == 0) {
					argument.algorithm = 0;
				}
				if (strcmp(optarg, "serpent") == 0) {
					argument.algorithm = 1;
				}
				if (strcmp(optarg, "camillia") == 0) {
					argument.algorithm = 2;
				}
				break;
			case 'b':
				bs = atoi(optarg);
				break;
				
			case 'r':
				argument.remove_ifile_flag = 1;
				break;
			case 'H':
				argument.headless_flag = 1;
				break;
			case 'h':
				argument.help_flag = 1;
				break;
			case 'w':
				argument.overwrite_flag = 1;
				break;
		}
	}
	if(argument.help_flag != 0) {
		show_help(argv);
		return 0;
	}
	if(check <3) {
		printf("Insufficient arguments\n");
		return 0;
	}
	if(bs<16 || bs>2147483648 || bs%16 != 0) {
		printf("Invalid blocksize\n");
		return 0;
	}
	
	if(argument.operation == 3) {
		printf("Invalid Operation\n");
		return 0;
	}
	if ((argument.in = (fopen(argument.infile, "rb"))) == NULL && !argument.headless_flag) {
		printf("Infile is not accessible\n");
		return 0;
	}
	if ((argument.out = (fopen(argument.outfile, "rb"))) != NULL) {
		if(!argument.headless_flag && !argument.overwrite_flag) {
			printf("Outfile already exists");
			return 0;
		}
	}
	if((argument.out = (fopen(argument.outfile, "wb"))) == NULL) {
		printf("Error creating new file\n");
		return 0;
	}
	
	// Advanced Buffers  
	BYTE * salt = (BYTE*) calloc(32, 1);
	BYTE * key = (BYTE*) calloc(32, 1);
	BYTE * hash = (BYTE*) calloc(32,1 );
	BYTE *taker;
	BYTE *watermark = (BYTE*)calloc(30,1);
	BYTE *comp_watermark = (BYTE*) calloc(30,1);
	BYTE *iv = calloc(16, 1);
	BYTE comp_algorithm;
	BYTE *comp_hash = (BYTE*) calloc(32,1);
	BYTE leftover;
	gcry_md_hd_t hash_instance;
	iv = "_initialization_";
	watermark = "This is the libnorc watermark:";
	unsigned long long int len;
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
	
	
	switch(argument.operation) {
		case 1: // ################################################################ Encrypt ############################################################### //
			if(password_veri(argument.password) != 0) {
				printf("Inputs do not match\n");
				remove(argument.outfile);
				return 0;
			}
			
			// Build key
			gcry_randomize (salt, 32, GCRY_VERY_STRONG_RANDOM); // generate salt
			gcry_md_open (&hash_instance, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE); // Create key to use for the encryption
			gcry_md_write (hash_instance, argument.password, 128);
			gcry_md_write (hash_instance, salt, 32);
			gcry_md_final (hash_instance);
			taker = gcry_md_read(hash_instance, GCRY_MD_SHA256);
			for(i=0; i<32; i++) {
				key[i] = taker[i]; // Copy Key into 'key'
			}
			gcry_md_reset (hash_instance);
			gcry_md_write (hash_instance, key, 32);
			gcry_md_final (hash_instance);
			taker = gcry_md_read(hash_instance, GCRY_MD_SHA256);
			for(i=0; i<32; i++) {
				hash[i] = taker[i]; // Copy Key into 'hash'
			}
			
			// gcry_md_reset (hash_instance);
			fseek(argument.in, 0, SEEK_END);
			len = ftell(argument.in);
			fseek(argument.in, 0, SEEK_SET);
			leftover = len%16;
			
			
			write_metadata96(argument.out, watermark, argument.algorithm, &leftover, salt, hash);
			check = encrypt_data(argument.in, argument.out, argument.algorithm, argument.operation, len%16, key, iv, bs);
			// printf("Library exited with returnvalue %d\n", check);
			break; // ################################################################ Decrypt ############################################################### //
		case 2:
			read_metadata96(argument.in, comp_watermark, &comp_algorithm, &leftover,salt,hash);
			
			if(strcmp(comp_watermark, watermark)!=0 && !argument.headless_flag) {
				printf("Infile is not encrypted\n");
				return 0;
			}
			
			if(comp_algorithm != argument.algorithm && !argument.headless_flag) {
				printf("Infile was not encrypted using specified algorithm\nUsing algorithm hints hidden in header sector instead...\n");
				argument.algorithm = comp_algorithm;
			}
			password_noveri(argument.password); // Ask for pw
			
			
			gcry_md_open (&hash_instance, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE); // Create key to use for the encryption
			gcry_md_write (hash_instance, argument.password, 128);
			gcry_md_write (hash_instance, salt, 32);
			gcry_md_final (hash_instance);
			taker = gcry_md_read(hash_instance, GCRY_MD_SHA256);
			for(i=0; i<32; i++) {
				key[i] = taker[i]; // Copy Key into 'key'
			}
			gcry_md_reset (hash_instance);
			gcry_md_write (hash_instance, key, 32);
			gcry_md_final (hash_instance);
			taker = gcry_md_read(hash_instance, GCRY_MD_SHA256);
			for(i=0; i<32; i++) {
				comp_hash[i] = taker[i]; // Copy Key into 'hash'
			}
			
			if(*comp_hash != *hash && !argument.headless_flag) {
				printf("Hash Mismatch!\nPassword incorrect\n");
				remove (argument.outfile);
				return 0;
			}
			
			
			check = decrypt_data(argument.in, argument.out, argument.algorithm, argument.operation, leftover, key, iv, bs);
			// printf("Library exited with returnvalue %d\n", check);
			break; 
		case 0: // ################################################################ Idle Mode ############################################################# //
			return 0; 
		case 3: // ########################################################## Bad Operation Mode ########################################################## //
			printf("Invalid Operation\n");
			return 0;
	}
	if(argument.remove_ifile_flag) {
		check = remove (argument.infile);
		if(check) {
			printf("Failed to remove file\n");
		}
	}	
}













