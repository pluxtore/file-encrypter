typedef unsigned char BYTE;
int read_metadata96(FILE *, BYTE*, BYTE*, BYTE*, BYTE*, BYTE*);
int write_metadata96(FILE *, BYTE*, BYTE, BYTE*, BYTE*, BYTE*);
int decrypt_data(FILE*, FILE*, BYTE, BYTE, BYTE, BYTE*, BYTE*, unsigned int);
int encrypt_data(FILE*, FILE*, BYTE, BYTE, BYTE, BYTE*, BYTE*, unsigned int);
int password_veri(char*);
int password_noveri(char*);
 
