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

int main(int argc, char **argv) {

	int verbose = 0;
	unsigned char *password = NULL;
	int password_len;

	unsigned char *input;
	int input_len = 1;
	unsigned char *encryption_buffer;
	unsigned char *output_buffer;
	int encryption_buffer_len;
	int output_buffer_len;
	int output_len;

	unsigned char buffer[BUF_SIZE];

	int option;
	seal_t mode = SEAL;
	Options encryption_options = DEFAULT_ENCRYPTION_OPTIONS;
	Options integrity_options = DEFAULT_INTEGRITY_OPTIONS;

	struct CironContext ctx;


	opterr = 0;

	while ((option = getopt(argc, argv, "-hvsup:")) != EOF) {
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

	if ((input = malloc(sizeof(char) * BUF_SIZE)) == NULL ) {
		perror("Failed to allocate input buffer");
		exit(3);
	}

	/* Read all input at once */
	input[0] = '\0';
	while (fgets((char *)buffer, sizeof(buffer), stdin)) {
		unsigned char *old = input;
		input_len += strlen((char*)buffer);
		if ((input = realloc(input, input_len)) == NULL ) {
			perror("Failed to reallocate input buffer");
			free(old);
			free(password);
			exit(4);
		}
		strcat((char*)input, (char*)buffer);
	}
	if(verbose) {
		fprintf(stderr,"Read %d bytes of input\n", input_len);
	}


	encryption_buffer_len = calculate_encryption_buffer_length(encryption_options, input_len);
	if( (encryption_buffer = malloc(encryption_buffer_len)) == NULL) {
		perror("Unable to allocate encryption buffer");
		free(password);
		free(input);
		exit(5);
	}

	if(verbose) {
		fprintf(stderr,"Allocated %d bytes for encryption buffer\n", encryption_buffer_len);
	}


	/* Below we add 1 byte because we want to \0-terminate the buffer */
	if (mode == SEAL) {
		output_buffer_len = calculate_seal_buffer_length(encryption_options, integrity_options, input_len) + 1;
	} else {
		output_buffer_len = calculate_unseal_buffer_length(encryption_options, integrity_options, input_len) + 1;
	}
	if(verbose) {
			fprintf(stderr,"Will allocate %d bytes for output buffer\n", output_buffer_len);
	}

	if( (output_buffer = malloc(output_buffer_len)) == NULL) {
		perror("Unable to allocate output buffer");
		free(password);
		free(input);
		free(encryption_buffer);
		exit(6);
	}

	if(verbose) {
		fprintf(stderr,"Allocated %d bytes for output buffer\n", output_buffer_len);
	}

	if (mode == SEAL) {
		if( (ciron_seal(&ctx,input, input_len, password, password_len,
				encryption_options, integrity_options, encryption_buffer,
				output_buffer, &output_len)) != CIRON_OK) {
			fprintf(stderr,"Unable to seal: %s\n" , ciron_get_error(&ctx));
			exit(8);
		}
	} else {
		CironError e;
		if( (e =ciron_unseal(&ctx,input, input_len, password, password_len,
				encryption_options, integrity_options, encryption_buffer,
				output_buffer, &output_len)) != CIRON_OK) {
			if(e == CIRON_TOKEN_PARSE_ERROR) {
				fprintf(stderr,"Invalid token format, %s\n" , ciron_get_error(&ctx));
				exit(7);
			}
			fprintf(stderr,"Unable to unseal: %s\n" , ciron_get_error(&ctx));
			exit(8);

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
	printf("    -h               show this screen\n");
	printf("    -v               verbose mode to print some diagnostic messages\n");
	printf("    -p <password>    password to use for sealing/unsealing\n");
	printf("    -s               seal the input (this is the default)\n");
	printf("    -u               unseal the input\n");
	printf("\n");
}
