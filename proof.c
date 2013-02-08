#include <assert.h>
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


static long var_index_mask = 0x00FFFFFF;
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
	mpz_init_set(proof->consts[var & var_index_mask], value);
	return var;
}

var_t new_const_ui(proof_t proof, unsigned long int value) {
	var_t var = alloc_const(proof);
	mpz_init_set_ui(proof->consts[var & var_index_mask], value);
	return var;
}

mpz_ptr get_const(proof_t proof, var_t var) {
	assert((var_type_mask & var) == var_type_const);
	return proof->consts[var & var_index_mask];
}


void instance_init_prover(proof_t proof, instance_t instance) {
	int i;
	instance->secret_values = pbc_malloc(proof->num_secret * sizeof(mpz_t));
	instance->secret_openings = pbc_malloc(proof->num_secret * sizeof(mpz_t));
	instance->secret_commitments = pbc_malloc(proof->num_secret * sizeof(element_t));
	for (i = 0; i < proof->num_secret; i++) {
		mpz_init(instance->secret_values[i]);
		mpz_init(instance->secret_openings[i]);
		element_init_same_as(instance->secret_commitments[i], proof->g);
	}
	
	instance->public_values = pbc_malloc(proof->num_public * sizeof(mpz_t));
	for (i = 0; i < proof->num_public; i++) {
		mpz_init(instance->public_values[i]);
	}
}

void instance_init_verifier(proof_t proof, instance_t instance) {
	int i;
	instance->secret_values = NULL;
	instance->secret_openings = NULL;
	instance->secret_commitments = pbc_malloc(proof->num_secret * sizeof(element_t));
	for (i = 0; i < proof->num_secret; i++) {
		element_init_same_as(instance->secret_commitments[i], proof->g);
	}
	
	instance->public_values = pbc_malloc(proof->num_public * sizeof(mpz_t));
	for (i = 0; i < proof->num_public; i++) {
		mpz_init(instance->public_values[i]);
	}
}

void instance_clear(proof_t proof, instance_t instance) {
	int i;
	if (instance->secret_values != NULL) {
		for (i = 0; i < proof->num_secret; i++) {
			mpz_clear(instance->secret_values[i]);
			mpz_clear(instance->secret_openings[i]);
			element_free(instance->secret_commitments[i]);
		}
		pbc_free(instance->secret_values);
		pbc_free(instance->secret_openings);
	} else {
		for (i = 0; i < proof->num_secret; i++) {
			element_free(instance->secret_commitments[i]);
		}
	}
	pbc_free(instance->secret_commitments);
	
	for (i = 0; i < proof->num_public; i++) {
		mpz_clear(instance->public_values[i]);
	}
	pbc_free(instance->public_values);
}

void set(proof_t proof, instance_t instance, var_t var, mpz_t value) {
	long type = var_type_mask & var;
	long index = var_index_mask & var;
	if (type == var_type_secret) {
		mpz_set(instance->secret_values[index], value);
		pbc_mpz_random(instance->secret_openings[index], proof->g->field->order);
		element_pow2_mpz(instance->secret_commitments[index], // C_x = g^x h^(o_x)
			proof->g, instance->secret_values[index],
			proof->h, instance->secret_openings[index]);
	} else if (type == var_type_public) {
		mpz_set(instance->public_values[index], value);
	} else assert(0);
}

mpz_ptr get(proof_t proof, instance_t instance, var_t var) {
	long type = var_type_mask & var;
	long index = var_index_mask & var;
	if (type == var_type_secret) return instance->secret_values[index];
	else if (type == var_type_public) return instance->public_values[index];
	else return proof->consts[index];
}
