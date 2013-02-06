#include <pbc.h>
#include <stdio.h>
#include "sig.h"

int main() {
	pairing_t pairing;
	
	FILE* fparam = fopen("a.param", "rb");
	char param[1024];
	size_t count = fread(param, 1, 1024, fparam);
	fclose(fparam);
	if (!count) pbc_die("input error");
	pairing_init_set_buf(pairing, param, count);
	
	key_secret_t secret_key;
	key_public_t public_key;
	key_init_random(secret_key, public_key, pairing, 3);
	
	sig_t sig;
	sig_init(sig, pairing, 3);
	
	mpz_t message[3];
	mpz_init_set_ui(message[0], 24);
	mpz_init_set_ui(message[1], 193);
	mpz_init_set_ui(message[2], 297);
	
	sig_sign_mpz(sig, secret_key, message, 3);
	
	int result = sig_verify_mpz(sig, public_key, pairing, message, 3);
	
	
	
	return 0;
}
