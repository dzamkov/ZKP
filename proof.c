#include <assert.h>
#include "zkp.h"
#include "zkp_internal.h"

void proof_init(proof_t proof, element_t g, element_t h) {
	proof->num_secret = 0;
	proof->num_public = 0;
	element_init_same_as(proof->g, g); element_set(proof->g, g);
	element_init_same_as(proof->h, h); element_set(proof->h, h);
	
	proof->first_public_computation = NULL;
	proof->last_public_computation = NULL;
	proof->first_secret_computation = NULL;
	proof->last_secret_computation = NULL;
	
	proof->first_block = NULL;
	proof->last_block = NULL;
	proof->witness_extra_size = 0;
}

void proof_clear(proof_t proof) {
	element_clear(proof->g);
	element_clear(proof->h);
	computations_clear(proof);
	blocks_clear(proof);
}

const long VAR_SECRET_FLAG = 0x80000000;
const long VAR_INDEX_MASK = 0x7FFFFFFF;

var_t var_secret(proof_t proof) {
	var_t var = VAR_SECRET_FLAG | proof->num_secret;
	proof->num_secret++;
	return var;
}

var_t var_public(proof_t proof) {
	var_t var = proof->num_public;
	proof->num_public++;
	return var;
}

int var_is_secret(var_t var) {
	return var & VAR_SECRET_FLAG;
}

int var_is_public(var_t var) {
	return (var & VAR_SECRET_FLAG) == 0;
}

long var_index(var_t var) {
	return var & VAR_INDEX_MASK;
}

void inst_init_prover(proof_t proof, inst_t inst) {
	int i;
	inst->secret_values = pbc_malloc(proof->num_secret * sizeof(mpz_t));
	inst->secret_openings = pbc_malloc(proof->num_secret * sizeof(mpz_t));
	inst->secret_commitments = pbc_malloc(proof->num_secret * sizeof(element_t));
	for (i = 0; i < proof->num_secret; i++) {
		mpz_init(inst->secret_values[i]);
		mpz_init(inst->secret_openings[i]);
		element_init_same_as(inst->secret_commitments[i], proof->g);
	}
	
	inst->public_values = pbc_malloc(proof->num_public * sizeof(mpz_t));
	for (i = 0; i < proof->num_public; i++) {
		mpz_init(inst->public_values[i]);
	}
}

void inst_init_verifier(proof_t proof, inst_t inst) {
	int i;
	inst->secret_values = NULL;
	inst->secret_openings = NULL;
	inst->secret_commitments = pbc_malloc(proof->num_secret * sizeof(element_t));
	for (i = 0; i < proof->num_secret; i++) {
		element_init_same_as(inst->secret_commitments[i], proof->g);
	}
	
	inst->public_values = pbc_malloc(proof->num_public * sizeof(mpz_t));
	for (i = 0; i < proof->num_public; i++) {
		mpz_init(inst->public_values[i]);
	}
}

void inst_clear(proof_t proof, inst_t inst) {
	int i;
	if (inst->secret_values != NULL) {
		for (i = 0; i < proof->num_secret; i++) {
			mpz_clear(inst->secret_values[i]);
			mpz_clear(inst->secret_openings[i]);
			element_free(inst->secret_commitments[i]);
		}
		pbc_free(inst->secret_values);
		pbc_free(inst->secret_openings);
	} else {
		for (i = 0; i < proof->num_secret; i++) {
			element_free(inst->secret_commitments[i]);
		}
	}
	pbc_free(inst->secret_commitments);
	
	for (i = 0; i < proof->num_public; i++) {
		mpz_clear(inst->public_values[i]);
	}
	pbc_free(inst->public_values);
}

void update_secret_commitment(proof_t proof, inst_t inst, long index) {
	pbc_mpz_random(inst->secret_openings[index], proof->g->field->order);
	element_pow2_mpz(inst->secret_commitments[index], // C_x = g^x h^(o_x)
		proof->g, inst->secret_values[index],
		proof->h, inst->secret_openings[index]);
}

void inst_var_set(proof_t proof, inst_t inst, var_t var, mpz_t value) {
	if (var_is_secret(var)) {
		assert(inst->secret_values != NULL);
		mpz_set(inst->secret_values[var_index(var)], value);
		update_secret_commitment(proof, inst, var_index(var));
	} else {
		mpz_set(inst->public_values[var_index(var)], value);
	}
}

void inst_var_set_ui(proof_t proof, inst_t inst, var_t var, unsigned long int value) {
	if (var_is_secret(var)) {
		assert(inst->secret_values != NULL);
		mpz_set_ui(inst->secret_values[var_index(var)], value);
		update_secret_commitment(proof, inst, var_index(var));
	} else {
		mpz_set_ui(inst->public_values[var_index(var)], value);
	}
}

void inst_var_set_si(proof_t proof, inst_t inst, var_t var, signed long int value) {
	if (var_is_secret(var)) {
		assert(inst->secret_values != NULL);
		mpz_set_si(inst->secret_values[var_index(var)], value);
		update_secret_commitment(proof, inst, var_index(var));
	} else {
		mpz_set_si(inst->public_values[var_index(var)], value);
	}
}

mpz_ptr inst_var_get(proof_t proof, inst_t inst, var_t var) {
	if (var_is_secret(var)) {
		assert(inst->secret_values != NULL);
		return inst->secret_values[var_index(var)];
	} else return inst->public_values[var_index(var)];
}

size_t inst_var_out_raw(FILE* stream, proof_t proof, inst_t inst, var_t var) {
	return mpz_out_raw(stream, inst_var_get(proof, inst, var));
}

size_t inst_var_inp_raw(proof_t proof, inst_t inst, var_t var, FILE* stream) {
	if (var_is_secret(var)) {
		assert(inst->secret_values != NULL);
		size_t size = mpz_inp_raw(inst->secret_values[var_index(var)], stream);
		update_secret_commitment(proof, inst, var_index(var));
		return size;
	} else {
		return mpz_inp_raw(inst->public_values[var_index(var)], stream);
	}
}

size_t inst_commitment_out_raw(FILE* stream, proof_t proof, inst_t inst, var_t var) {
	assert(var_is_secret(var));
	return element_out_raw(stream, inst->secret_commitments[var_index(var)]);
}

size_t inst_commitment_inp_raw(proof_t proof, inst_t inst, var_t var, FILE* stream) {
	assert(var_is_secret(var));
	return element_inp_raw(inst->secret_commitments[var_index(var)], stream);
}

size_t inst_commitments_out_raw(FILE* stream, proof_t proof, inst_t inst) {
	int i;
	size_t len = 0;
	for (i = 0; i < proof->num_secret; i++) {
		len += element_out_raw(stream, inst->secret_commitments[i]);
	}
	return len;
}

size_t inst_commitments_inp_raw(proof_t proof, inst_t inst, FILE* stream) {
	int i;
	size_t len = 0;
	for (i = 0; i < proof->num_secret; i++) {
		len += element_inp_raw(inst->secret_commitments[i], stream);
	}
	return len;
}
