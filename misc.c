#include <stdint.h>
#include "zkp.h"
#include "zkp_internal.h"

void* alloca(size_t);
size_t element_out_raw(FILE* stream, element_t element) {
	uint32_t size = element_length_in_bytes(element);
	unsigned char *data = (unsigned char*)alloca(4 + size);
	data[0] = size >> 24;
	data[1] = size >> 16;
	data[2] = size >> 8;
	data[3] = size >> 0;
	element_to_bytes(data + 4, element);
	return fwrite(data, 1, 4 + size, stream);
}

size_t element_inp_raw(element_t element, FILE* stream) {
	unsigned char size_data[4];
	size_t len = fread(size_data, 1, 4, stream);
	uint32_t size = (size_data[0] << 24) | (size_data[1] << 16) | (size_data[2] << 8) | (size_data[3] << 0);
	unsigned char *data = (unsigned char*)alloca(size);
	len += fread(data, 1, size, stream);
	element_from_bytes(element, data);
	return len;
}

int mpz_decompose_prime(mpz_t a, mpz_t b, mpz_t n) {
	// f = n - 1
	mpz_t f; mpz_init(f);
	mpz_sub_ui(f, n, 1);
	
	// if n = 5 (mod 8)
	if (mpz_congruent_ui_p(n, 5, 8)) {
		
		// b = 2
		mpz_set_ui(b, 2);
		
		// f = (n - 1) / 4
		mpz_tdiv_q_2exp(f, f, 2);
		
	} else  {
		
		// b = 3
		mpz_set_ui(b, 3);
		
		// f = (n - 1) / 2
		mpz_tdiv_q_2exp(f, f, 1);
		
		// t = b ^ ((n - 1) / 2) (mod n)
		mpz_t t; mpz_init(t);
		mpz_powm(t, b, f, n);
		
		// while b ^ ((n - 1) / 2) = 1 (mod n)
		while (!mpz_cmp_ui(t, 1)) {
			
			// b = next prime after b
			mpz_nextprime(b, b);
			
			// t = b ^ ((n - 1) / 2) (mod n)
			mpz_powm(t, b, f, n);
		}
		
		// f = (n - 1) / 4
		mpz_tdiv_q_2exp(f, f, 1);
		
		mpz_clear(t);
	}
	
	// b = b ^ ((n - 1) / 4) (mod n)
	// b ^ 2 = -1 (mod n)
	mpz_powm(b, b, f, n);
	
	// a = n
	mpz_set(a, n);
	
	// bb = b ^ 2
	mpz_t bb; mpz_init(bb);
	mpz_mul(bb, b, b);
	
	// while b ^ 2 > p
	while (mpz_cmp(bb, n) > 0) {
		
		// a = b
		// b = a % b
		mpz_set(f, a);
		mpz_set(a, b);
		mpz_mod(b, f, b);
		
		// bb = b ^ 2
		mpz_mul(bb, b, b);
	}
	mpz_clear(bb);
	
	// a = a % b
	mpz_mod(a, a, b);
	
	// verify a ^ 2 + b ^ 2 = n
	mpz_mul(f, a, a);
	mpz_addmul(f, b, b);
	int res = !mpz_cmp(f, n);
	
	mpz_clear(f);
	return res;
	
}

void mpz_decompose(mpz_t a, mpz_t b, mpz_t c, mpz_t d, mpz_t n) {
	unsigned long v;
	
	// Find the largest a such that n - a ^ 2 is not in the form
	// 4 ^ t (7 + 8k) for some t and k.
	mpz_t r; mpz_init(r);
	mpz_sqrt(a, n);
	for (;;) {
		
		// r = n - a ^ 2
		mpz_set(r, n);
		mpz_submul(r, a, a);
		if (mpz_perfect_square_p(r)) {
			
			// Looks like we found out that n = a ^ 2 + r ^ 2.
			mpz_sqrt(b, r);
			mpz_set_ui(c, 0);
			mpz_set_ui(d, 0);
			mpz_clear(r);
			return;
		}
		
		// factor the largest possible (4 ^ v) out of r
		v = 0;
		while (mpz_divisible_2exp_p(r, 2)) {
			v++;
			mpz_tdiv_q_2exp(r, r, 2);
		}
		
		// verify r != 7 (mod 8)
		if (!mpz_congruent_ui_p(r, 7, 8)) break;
		
		// else, a = a - 1
		mpz_sub_ui(a, a, 1);
	}
	
	// The problem has been reduced to expressing r as a sum
	// of three squares.
	
	// Check if r is a special case that can not be expressed
	// as the sum of a square and a prime or twice a prime. 
	// If so, look up the precomputed decomposition for it.
	if (mpz_fits_ushort_p(r)) {
		unsigned short rn = (unsigned short)mpz_get_ui(r);
		switch(rn) {
			case 0: mpz_set_ui(b, 0); mpz_set_ui(c, 0); mpz_set_ui(d, 0); goto end;
			case 1: mpz_set_ui(b, 1); mpz_set_ui(c, 0); mpz_set_ui(d, 0); goto end;
			case 2: mpz_set_ui(b, 1); mpz_set_ui(c, 1); mpz_set_ui(d, 0); goto end;
			case 3: mpz_set_ui(b, 1); mpz_set_ui(c, 1); mpz_set_ui(d, 1); goto end;
			case 10: mpz_set_ui(b, 3); mpz_set_ui(c, 1); mpz_set_ui(d, 0); goto end;
			case 34: mpz_set_ui(b, 4); mpz_set_ui(c, 3); mpz_set_ui(d, 3); goto end;
			case 58: mpz_set_ui(b, 7); mpz_set_ui(c, 3); mpz_set_ui(d, 0); goto end;
			case 85: mpz_set_ui(b, 7); mpz_set_ui(c, 6); mpz_set_ui(d, 0); goto end;
			case 130: mpz_set_ui(b, 11); mpz_set_ui(c, 3); mpz_set_ui(d, 0); goto end;
			case 214: mpz_set_ui(b, 13); mpz_set_ui(c, 6); mpz_set_ui(d, 3); goto end;
			case 226: mpz_set_ui(b, 9); mpz_set_ui(c, 9); mpz_set_ui(d, 8); goto end;
			case 370: mpz_set_ui(b, 15); mpz_set_ui(c, 9); mpz_set_ui(d, 8); goto end;
			case 526: mpz_set_ui(b, 21); mpz_set_ui(c, 7); mpz_set_ui(d, 6); goto end;
			case 706: mpz_set_ui(b, 16); mpz_set_ui(c, 15); mpz_set_ui(d, 15); goto end;
			case 730: mpz_set_ui(b, 27); mpz_set_ui(c, 1); mpz_set_ui(d, 0); goto end;
			case 1414: mpz_set_ui(b, 33); mpz_set_ui(c, 17); mpz_set_ui(d, 6); goto end;
			case 1906: mpz_set_ui(b, 36); mpz_set_ui(c, 21); mpz_set_ui(d, 13); goto end;
			case 2986: mpz_set_ui(b, 39); mpz_set_ui(c, 32); mpz_set_ui(d, 21); goto end;
			case 9634: mpz_set_ui(b, 57); mpz_set_ui(c, 57); mpz_set_ui(d, 56); goto end;
		}
	}
	
	// If r = 3 (mod 8)
	mpz_t p; mpz_init(p);
	if (mpz_congruent_ui_p(r, 3, 8)) {
		mpz_t x; mpz_init(x);
		mpz_t y; mpz_init(y);
	
		// Find the largest odd b such that (r - b ^ 2) / 2 is a prime.
		mpz_sqrt(b, r); if (mpz_even_p(b)) mpz_sub_ui(b, b, 1);
		for (;;) {
		
			// p = (r - b ^ 2) / 2
			mpz_set(p, r);
			mpz_submul(p, b, b);
			mpz_tdiv_q_2exp(p, p, 1);
			
			// verify p is a prime.
			if (mpz_probab_prime_p(p, 20)) {
			
				// decompose p.
				if (mpz_decompose_prime(x, y, p)) {
					
					// c = x + y
					mpz_add(c, x, y);
					
					// d = abs (x - y)
					mpz_sub(d, x, y);
					mpz_abs(d, d);
				
					break;
				}
			}
		
			// b = b - 2
			mpz_sub_ui(b, b, 2);
		}
		
		mpz_clear(x);
		mpz_clear(y);
	} else {
		
		// Find the largest b such that r - b ^ 2 is a prime.
		mpz_sqrt(b, r); if (mpz_even_p(r) ^ mpz_odd_p(b)) mpz_sub_ui(b, b, 1);
		for (;;) {
		
			// p = r - b ^ 2
			mpz_set(p, r);
			mpz_submul(p, b, b);
			
			// verify p is a prime.
			if (mpz_probab_prime_p(p, 20)) {
			
				// decompose p into c and d.
				if (mpz_decompose_prime(c, d, p)) break;
			}
		
			// b = b - 2
			mpz_sub_ui(b, b, 2);
		}
	
	}
	
end:
	mpz_mul_2exp(b, b, v);
	mpz_mul_2exp(c, c, v);
	mpz_mul_2exp(d, d, v);
	mpz_clear(r);
	mpz_clear(p);
}
