#include <assert.h>
#include <pbc.h>
#include "proof.h"

void proof_init(proof_t proof, element_t g, element_t h) {
	proof->num_secret = 0;
	proof->num_public = 0;
	proof->num_const = 0;
	proof->num_extra_G = 0;
	proof->num_extra_Z = 0;
	element_init_same_as(proof->g, g); element_set(proof->g, g);
	element_init_same_as(proof->h, h); element_set(proof->h, h);
	
	proof->first_public_computation = NULL;
	proof->last_public_computation = NULL;
	proof->first_secret_computation = NULL;
	proof->last_secret_computation = NULL;
}

void clear_computations(struct computation_s *first);
void proof_clear(proof_t proof) {
	element_clear(proof->g);
	element_clear(proof->h);
	clear_computations(proof->first_public_computation);
}

static long var_secret_flag = 0x80000000;
static long var_index_mask = 0x7FFFFFFF;

var_t new_secret(proof_t proof) {
	var_t var = var_secret_flag | proof->num_secret;
	proof->num_secret++;
	return var;
}

var_t new_public(proof_t proof) {
	var_t var = proof->num_public;
	proof->num_public++;
	return var;
}

void compute_assign(proof_t proof, var_t var, mpz_t value);
var_t new_const(proof_t proof, mpz_t value) {
	var_t var = new_public(proof);
	compute_assign(proof, var, value);
	return var;
}

void compute_assign_ui(proof_t proof, var_t var, unsigned long int value);
var_t new_const_ui(proof_t proof, unsigned long int value) {
	var_t var = new_public(proof);
	compute_assign_ui(proof, var, value);
	return var;
}

void compute_assign_si(proof_t proof, var_t var, signed long int value);
var_t new_const_si(proof_t proof, signed long int value) {
	var_t var = new_public(proof);
	compute_assign_si(proof, var, value);
	return var;
}

int is_secret(var_t var) {
	return var & var_secret_flag;
}

int is_public(var_t var) {
	return (var & var_secret_flag) == 0;
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

void inst_set(proof_t proof, inst_t inst, var_t var, mpz_t value) {
	long index = var & var_index_mask;
	if (is_secret(var)) {
		assert(inst->secret_values != NULL);
		mpz_set(inst->secret_values[index], value);
		update_secret_commitment(proof, inst, index);
	} else {
		mpz_set(inst->public_values[index], value);
	}
}

void inst_set_ui(proof_t proof, inst_t inst, var_t var, unsigned long int value) {
	long index = var & var_index_mask;
	if (is_secret(var)) {
		assert(inst->secret_values != NULL);
		mpz_set_ui(inst->secret_values[index], value);
		update_secret_commitment(proof, inst, index);
	} else {
		mpz_set_ui(inst->public_values[index], value);
	}
}

void inst_set_si(proof_t proof, inst_t inst, var_t var, signed long int value) {
	long index = var & var_index_mask;
	if (is_secret(var)) {
		assert(inst->secret_values != NULL);
		mpz_set_si(inst->secret_values[index], value);
		update_secret_commitment(proof, inst, index);
	} else {
		mpz_set_si(inst->public_values[index], value);
	}
}

mpz_ptr inst_get(proof_t proof, inst_t inst, var_t var) {
	long index =  var & var_index_mask;
	if (is_secret(var)) {
		assert(inst->secret_values != NULL);
		return inst->secret_values[index];
	} else return inst->public_values[index];
}

void apply_computations(struct computation_s*, struct computation_s*,  proof_t, inst_t);
void inst_update(proof_t proof, inst_t inst) {
	if (inst->secret_values != NULL) {
		apply_computations(proof->first_public_computation, NULL, proof, inst);
	} else {
		apply_computations(proof->first_public_computation, proof->first_secret_computation, proof, inst);
	}
}
