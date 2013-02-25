#ifndef ZKP_SIG_H_
#define ZKP_SIG_H_

struct key_secret_s {
	mpz_t x;
	mpz_t y;
	mpz_t* z;
};
typedef struct key_secret_s *key_secret_ptr;
typedef struct key_secret_s key_secret_t[1];

void key_secret_init(key_secret_t secret_key, int n);
void key_secret_clear(key_secret_t secret_key, int n);


struct key_public_s {
	element_t g;
	element_t X;
	element_t Y;
	element_t* Z;
};
typedef struct key_public_s *key_public_ptr;
typedef struct key_public_s key_public_t[1];

void key_public_init(key_public_t public_key, pairing_t pairing, int n);
void key_public_clear(key_public_t public_key, int n);

void key_init_random(key_secret_t secret_key, key_public_t public_key, pairing_t pairing, int n);


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
void sig_sign_mpz(sig_t sig, key_secret_t secret_key, mpz_t message[], int n);
void sig_sign(sig_t sig, key_secret_t secret_key, element_t message[], int n);
int sig_verify_mpz(sig_t sig, key_public_t public_key, pairing_t pairing, mpz_t message[], int n);
int sig_verify(sig_t sig, key_public_t public_key, pairing_t pairing, element_t message[], int n);
void sig_clear(sig_t sig, int n);

#endif // ZKP_SIG_H_
