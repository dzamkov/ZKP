#include "sig.h"

void key_secret_init(key_secret_t secret_key, int n) {
	int i;
	int l = n - 1;
	mpz_init(secret_key->x);
	mpz_init(secret_key->y);
	secret_key->z = pbc_malloc(l * sizeof(element_t));
	for (i = 0; i < l; i++) {
		mpz_init(secret_key->z[i]);
	}
}

void key_secret_clear(key_secret_t secret_key, int n) {
	int i;
	int l = n - 1;
	mpz_clear(secret_key->x);
	mpz_clear(secret_key->y);
	for (i = 0; i < l; i++) {
		mpz_clear(secret_key->z[i]);
	}
	pbc_free(secret_key->z);
}

void key_public_init(key_public_t public_key, pairing_t pairing, int n) {
	int i;
	int l = n - 1;
	element_init_G1(public_key->g, pairing);
	element_init_G1(public_key->X, pairing);
	element_init_G1(public_key->Y, pairing);
	public_key->Z = pbc_malloc(l * sizeof(element_t));
	for (i = 0; i < l; i++) {
		element_init_G1(public_key->Z[i], pairing);
	}
}

void key_public_clear(key_public_t public_key, int n) {
	int i;
	int l = n - 1;
	element_clear(public_key->g);
	element_clear(public_key->X);
	element_clear(public_key->Y);
	for (i = 0; i < l; i++) {
		element_clear(public_key->Z[i]);
	}
	pbc_free(public_key->Z);
}

void key_init_random(key_secret_t secret_key, key_public_t public_key, pairing_t pairing, int n) {
	int i;
	int l = n - 1;
	
	key_secret_init(secret_key, n);
	key_public_init(public_key, pairing, n);
	
	
	element_random(public_key->g);
	
	// X = g ^ x
	pbc_mpz_random(secret_key->x, pairing->G1->order);
	element_pow_mpz(public_key->X, public_key->g, secret_key->x);
	
	// Y = g ^ y
	pbc_mpz_random(secret_key->y, pairing->G1->order);
	element_pow_mpz(public_key->Y, public_key->g, secret_key->y);
	
	for (i = 0; i < l; i++) {
		
		// Z[i] = g ^ z[i]
		pbc_mpz_random(secret_key->z[i], pairing->G1->order);
		element_pow_mpz(public_key->Z[i], public_key->g, secret_key->z[i]);
	}
}

void sig_init(sig_t sig, pairing_t pairing, int n) {
	int i;
	int l = n - 1;
	element_init_G1(sig->a, pairing);
	element_init_G1(sig->b, pairing);
	element_init_G1(sig->c, pairing);
	sig->A = pbc_malloc(l * sizeof(element_t));
	sig->B = pbc_malloc(l * sizeof(element_t));
	for (i = 0; i < l; i++) {
		element_init_G1(sig->A[i], pairing);
		element_init_G1(sig->B[i], pairing);
	}
}

void sig_sign_mpz(sig_t sig, key_secret_t secret_key, mpz_t message[], int n) {
	int i;
	int l = n - 1;
	
	mpz_t xy, e_temp;
	mpz_init(xy);
	mpz_init(e_temp);
	
	element_t temp;
	element_init_same_as(temp, sig->a);

	// b = a ^ y
	element_random(sig->a);
	element_pow_mpz(sig->b, sig->a, secret_key->y);
	
	// c = a ^ (x + x * y * m[0])
	mpz_mul(xy, secret_key->x, secret_key->y);
	mpz_mul(e_temp, xy, message[0]);
	mpz_add(e_temp, e_temp, secret_key->x);
	element_pow_mpz(temp, sig->a, e_temp);
	element_set(sig->c, temp);
	
	for (i = 0; i < l; i++) {
		
		// A[i] = a ^ z[i]
		element_pow_mpz(sig->A[i], sig->a, secret_key->z[i]);
		
		// B[i] = A[i] ^ y
		element_pow_mpz(sig->B[i], sig->A[i], secret_key->y);
		
		// c = c * A[i] ^ (x * y * m[i + 1])
		mpz_mul(e_temp, xy, message[i + 1]);
		element_pow_mpz(temp, sig->A[i], e_temp);
		element_mul(sig->c, sig->c, temp);
	}
	
	mpz_clear(xy);
	mpz_clear(e_temp);
	element_clear(temp);
}

int verify_mpz(element_t left, element_t right, sig_t sig, 
	key_public_t public_key, pairing_t pairing, mpz_t message[], int n)
{
	int i;
	int l = n - 1;
	
	// e(a, Y) = e(g, b)
	pairing_apply(left, sig->a, public_key->Y, pairing);
	pairing_apply(right, public_key->g, sig->b, pairing);
	if (element_cmp(left, right)) return 0;

	for (i = 0; i < l; i++) {
		
		// e(a, Z[i]) = e(g, A[i])
		pairing_apply(left, sig->a, public_key->Z[i], pairing);
		pairing_apply(right, public_key->g, sig->A[i], pairing);
		if (element_cmp(left, right)) return 0;
		
		// e(A[i], Y) = e(g, B[i])
		pairing_apply(left, sig->A[i], public_key->Y, pairing);
		pairing_apply(right, public_key->g, sig->B[i], pairing);
		if (element_cmp(left, right)) return 0;
	}
	
	pairing_pp_t p;
	element_t temp;
	element_init_GT(temp, pairing);
	pairing_pp_init(p, public_key->X, pairing);
	
	// right = e(X, a) * e(X, b) ^ m[0]
	pairing_pp_apply(right, sig->a, p);
	pairing_pp_apply(temp, sig->b, p);
	element_pow_mpz(temp, temp, message[0]);
	element_mul(right, right, temp);
	
	for (i = 0; i < l; i++) {
		
		// right = right * e(X, B[i]) ^ m[i + 1]
		pairing_pp_apply(temp, sig->B[i], p);
		element_pow_mpz(temp, temp, message[i + 1]);
		element_mul(right, right, temp);
	}
	
	element_clear(temp);
	pairing_pp_clear(p);
	
	// e(g, c) = right
	pairing_apply(left, public_key->g, sig->c, pairing);
	if (element_cmp(left, right)) return 0;
	
	return 1;
}

int sig_verify_mpz(sig_t sig, key_public_t public_key, pairing_t pairing, mpz_t message[], int n) {
	element_t left, right;
	element_init_GT(left, pairing);
	element_init_GT(right, pairing);
	
	int result = verify_mpz(left, right, sig, public_key, pairing, message, n);

	element_clear(left);
	element_clear(right);
	return result;
}

void sig_clear(sig_t sig, int n) {
	int i;
	int l = n - 1;
	element_clear(sig->a);
	element_clear(sig->b);
	element_clear(sig->c);
	for (i = 0; i < l; i++) {
		element_clear(sig->A[i]);
		element_clear(sig->B[i]);
	}
	pbc_free(sig->A);
	pbc_free(sig->B);
}
