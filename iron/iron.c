#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ciron.h is the only header file you need to include. */
#include "ciron.h"

#define BUF_SIZE 1024

typedef enum mode {
	SEAL, UNSEAL
} seal_t;

void usage(void);
void help(void);

/*
 * A note on memory allocation: For improved code clarity, we do not
 * free up any allocated memory before exiting, although it would
 * be good practice to do so.
 */
int main(int argc, char **argv) {

	int verbose = 0;
	unsigned char *password = NULL;
	int password_len = 0;

	unsigned char *password_id = NULL;
	int password_id_len = 0;

	unsigned char *input;
	int input_len = 1;
	unsigned char *encryption_buffer;
	unsigned char *output_buffer;
	int encryption_buffer_len;
	int output_buffer_len;
	int output_len;

	unsigned char buffer[BUF_SIZE];

	struct CironPwdTableEntry pwd_table_entries[100];
	struct CironPwdTable pwd_table;

	int option;
	seal_t mode = SEAL;
	CironOptions encryption_options = CIRON_DEFAULT_ENCRYPTION_OPTIONS;
	CironOptions integrity_options = CIRON_DEFAULT_INTEGRITY_OPTIONS;

	struct CironContext ctx;

	pwd_table.entries = pwd_table_entries;
	pwd_table.nentries = 0;

	opterr = 0;

	while ((option = getopt(argc, argv, "-hvsup:i:")) != EOF) {
		switch (option) {
		case 'h':
			help();
			exit(0);
		case 'v':
			verbose = 1;
			break;
		case 's':
			mode = SEAL;
			break;
		case 'u':
			mode = UNSEAL;
			break;
		case 'p':
			password_len = strlen(optarg);
			if( (password = malloc(password_len)) == NULL) {
				perror("Unable to allocate password");
				exit(1);
			}
			strcpy((char*)password, optarg);
			break;
		case 'i':
			password_id_len = strlen(optarg);
			if( (password_id = malloc(password_id_len)) == NULL) {
				perror("Unable to allocate password_id");
				exit(1);
			}
			strcpy((char*)password_id, optarg);
			break;
		case '?':
			usage();
			exit(1);
		}
	}

	if(verbose) {
		fprintf(stderr,"Running in %s mode\n", (mode == SEAL) ? "SEAL" : "UNSEAL");
	}

	if (password == NULL) {
		usage();
		exit(2);
	}

	/*
	 * Check whether the password is actually a password table.
	 * Process if so.
	 */
	if(strstr((char*)password," ") != NULL) {
	     char *id, *pwd, *p;
	     int i = 0;
	     if(mode == SEAL) {
	    		 fprintf(stderr,"Seal mode requires password instead of table\n");
	    		 usage();
	    		 exit(3);

	     }

	     for (id = strtok_r((char*)password, " ", &p); id; id = strtok_r(NULL, " ", &p)) {
	    	 pwd_table.entries[i].password_id = (unsigned char*)id;
	    	 pwd_table.entries[i].password_id_len = strlen(id);

	    	 if( (pwd = strtok_r(NULL, " ", &p)) == NULL) {
	    		 fprintf(stderr,"Password table contains uneven number of elements\n");
	    		 usage();
	    		 exit(4);
	    	 }
	    	 pwd_table.entries[i].password = (unsigned char*)pwd;
	    	 pwd_table.entries[i].password_len = strlen(pwd);
	    	 i++;

	     }
	     password = NULL; /* Not needed anymore */
	     password_len = 0;

    	 pwd_table.nentries = i;
    	 if(verbose) {
    		 fprintf(stderr,"Storing id:pwd %s:%s\n" ,pwd_table.entries[i-1].password_id , pwd_table.entries[i-1].password );
    	 }
	}


	if ((input = malloc(sizeof(char) * BUF_SIZE)) == NULL ) {
		perror("Failed to allocate input buffer");
		exit(5);
	}

	/* Read all input at once */
	input[0] = '\0';
	while (fgets((char *)buffer, sizeof(buffer), stdin)) {
		input_len += strlen((char*)buffer);
		if ((input = realloc(input, input_len)) == NULL ) {
			perror("Failed to reallocate input buffer");
			exit(6);
		}
		strcat((char*)input, (char*)buffer);
	}
	if(verbose) {
		fprintf(stderr,"Read %d bytes of input\n", input_len);
	}
	/* Input len includes the \0 and we do not want to seal that */
	input_len--;

	/*
	 * seal() and unseal() require the caller to allocate a buffer for storing the
	 * binary encryption data, before it is base64url encoded into the result
	 * string. ciron provides a function to calculate the buffer size from the
	 * input data size.
	 */
	encryption_buffer_len = ciron_calculate_encryption_buffer_length(encryption_options, input_len);
	if( (encryption_buffer = malloc(encryption_buffer_len)) == NULL) {
		perror("Unable to allocate encryption buffer");
		exit(7);
	}

	if(verbose) {
		fprintf(stderr,"Allocated %d bytes for encryption buffer\n", encryption_buffer_len);
	}


	/*
	 * seal() and unseal() require the caller to allocate a buffer for storing the
	 * result. ciron provides a function to calculate the buffer size from the
	 * input data size.
	 */
	if (mode == SEAL) {
		/* We add 1 byte because we want to \0-terminate the buffer */
		output_buffer_len = ciron_calculate_seal_buffer_length(encryption_options, integrity_options, input_len,password_id_len) + 1;
	} else {
		/* We add 1 byte because we want to \0-terminate the buffer */
		output_buffer_len = ciron_calculate_unseal_buffer_length(encryption_options, integrity_options, input_len,password_id_len) + 1;
	}
	if(verbose) {
			fprintf(stderr,"Will allocate %d bytes for output buffer\n", output_buffer_len);
	}

	if( (output_buffer = malloc(output_buffer_len)) == NULL) {
		perror("Unable to allocate output buffer");
		exit(8);
	}

	if(verbose) {
		fprintf(stderr,"Allocated %d bytes for output buffer\n", output_buffer_len);
	}

	if (mode == SEAL) {
		/*
		fprintf(stderr, "%s", password);
		*/
		if( (ciron_seal(&ctx,input, input_len, password_id,password_id_len,password, password_len,
				encryption_options, integrity_options, encryption_buffer,
				output_buffer, &output_len)) != CIRON_OK) {
			fprintf(stderr,"Unable to seal: %s\n" , ciron_get_error(&ctx));
			exit(9);
		}
	} else {
		CironError e;
		/*
		fprintf(stderr, "(%s)", input);
		*/
		if( (e =ciron_unseal(&ctx,input, input_len, &pwd_table,password, password_len,
				encryption_options, integrity_options, encryption_buffer,
				output_buffer, &output_len)) != CIRON_OK) {
			if(e == CIRON_TOKEN_PARSE_ERROR) {
				fprintf(stderr,"Invalid token format, %s\n" , ciron_get_error(&ctx));
				exit(10);
			}
			fprintf(stderr,"Unable to unseal: %s\n" , ciron_get_error(&ctx));
			exit(11);

		}
	}
	if(verbose) {
		fprintf(stderr,"%s produced %d bytes of output\n", (mode == SEAL) ? "Sealing" : "Unsealing" , output_len);
	}
	output_buffer[output_len] = '\0';

	fprintf(stdout, "%s", output_buffer);


	return 0;
}

void usage(void) {
	printf("Usage: iron [-hvsu] -p <password>\n");
}

void help(void) {
	printf("\n");
	printf("iron - Sealing and unsealing encapulated tokens\n\n");
	printf("Reads UTF-8 encoded string from STDIN and seals or unseals the input to STDOUT\n\n");

	usage();

	printf("Options:\n");
	printf("    -h                          show this screen\n");
	printf("    -v                          verbose mode to print some diagnostic messages\n");
	printf("    -p <password>               password to use for sealing/unsealing\n");
	printf(" OR:-p \"id1 pwd1 id2 pwd2 ...\"  password table for password rotation\n");
	printf("    -i <password_id>            password_id of the supplied password to support password rotation\n");
	printf("    -s                          seal the input (this is the default)\n");
	printf("    -u                          unseal the input\n");
	printf("\n");
}
