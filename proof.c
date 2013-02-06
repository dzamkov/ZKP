#include "proof.h"

void proof_init(proof_t proof, element_t g, element_t h) {
	proof->num_secret = 0;
	proof->num_public = 0;
	proof->num_const = 0;
	proof->num_extra_G = 0;
	proof->num_extra_Z = 0;
	element_init_same_as(proof->g, g); element_set(proof->g, g);
	element_init_same_as(proof->h, h); element_set(proof->h, h);
	
	proof->consts = NULL;
}

void proof_clear(proof_t proof) {
	int i;
	element_clear(proof->g);
	element_clear(proof->h);
	if (proof->consts != NULL) {
		for (i = 0; i < proof->num_const; i++) {
			mpz_clear(proof->consts[i]);
		}
		pbc_free(proof->consts);
	}
}

static long var_value_mask = 0x00FFFFFF;
static long var_type_mask = 0xFF000000;
static long var_type_secret = 0x00000000;
static long var_type_public = 0x01000000;
static long var_type_const = 0x02000000;

var_t new_secret(proof_t proof) {
	var_t var = var_type_secret | proof->num_secret;
	proof->num_secret++;
	return var;
}

var_t new_public(proof_t proof) {
	var_t var = var_type_public | proof->num_public;
	proof->num_public++;
	return var;
}

var_t alloc_const(proof_t proof) {
	var_t var = var_type_const | proof->num_const;
	proof->num_const++;
	if (proof->consts == NULL) {
		proof->consts = pbc_malloc(proof->num_const * sizeof(mpz_t));
		proof->num_const_alloc = proof->num_const;
	} else if (proof->num_const > proof->num_const_alloc) {
		proof->num_const_alloc = proof->num_const_alloc * 2;
		proof->consts = pbc_realloc(proof->consts, proof->num_const_alloc * sizeof(mpz_t));
	}
	return var;
}

var_t new_const(proof_t proof, mpz_t value) {
	var_t var = alloc_const(proof);
	mpz_init_set(proof->consts[var & var_value_mask], value);
	return var;
}

var_t new_const_ui(proof_t proof, unsigned long int value) {
	var_t var = alloc_const(proof);
	mpz_init_set_ui(proof->consts[var & var_value_mask], value);
	return var;
}

mpz_ptr lookup_const(proof_t proof, var_t var) {
	return proof->consts[var & var_value_mask];
}
