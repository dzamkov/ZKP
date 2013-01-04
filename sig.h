#ifndef SIG_H_
#define SIG_H_

#include <pbc.h>

// A key for the CL-signature scheme.
struct key_s {
	element_t g;
	element_t x;
	element_t y;
	element_t* z;
};
typedef struct key_s *skey_ptr;
typedef struct key_s key_t[1];

void key_init_secret(key_t secret_key, pairing_t pairing, int n);
void key_init_public(key_t public_key, pairing_t pairing, int n);
void key_init_random(key_t secret_key, key_t public_key, pairing_t pairing, int n);
void key_clear(key_t key, int n);

// A signature on a multi-part message using the CL-signature scheme.
struct sig_s {
	element_t a;
	element_t* A;
	element_t b;
	element_t* B;
	element_t c;
};
typedef struct sig_s *sig_ptr;
typedef struct sig_s sig_t[1];

void sig_init(sig_t sig, pairing_t pairing, int n);
void sig_sign_mpz(sig_t sig, key_t secret_key, mpz_t message[], int n);
void sig_sign(sig_t sig, key_t secret_key, element_t message[], int n);
int sig_verify_mpz(sig_t sig, key_t public_key, pairing_t pairing, mpz_t message[], int n);
int sig_verify(sig_t sig, key_t public_key, pairing_t pairing, element_t message[], int n);
void sig_clear(sig_t sig, int n);

#endif // SIG_H_
