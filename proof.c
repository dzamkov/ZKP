#include <assert.h>
#include <pbc.h>
#include "zkp_io.h"
#include "zkp_proof.h"
#include "zkp_internal.h"

void _multi_init(type_ptr, data_ptr);
void _multi_clear(type_ptr, data_ptr);
void _multi_write(type_ptr, data_ptr, FILE*);
void _multi_read(type_ptr, data_ptr, FILE*);
type_ptr _supplement_type_for_block(block_ptr);
type_ptr _claim_secret_type_for_block(block_ptr);
type_ptr _claim_public_type_for_block(block_ptr);
type_ptr _response_type_for_block(block_ptr);
void multi_type_init(struct multi_type_s* type, proof_ptr proof, type_ptr (*for_block)(block_ptr)) {
	type->base->init = &_multi_init;
	type->base->clear = &_multi_clear;
	type->base->write = &_multi_write;
	type->base->read = &_multi_read;
	type->base->size = 0;
	type->proof = proof;
	type->for_block = for_block;
}

void proof_init(proof_t proof, field_ptr Z, field_ptr G, element_t g, element_t h) {
	element_type_init(proof->Z_type, Z);
	element_type_init(proof->G_type, G);
	multi_type_init(&proof->supplement_type, proof, &_supplement_type_for_block);
	multi_type_init(&proof->claim_secret_type, proof, &_claim_secret_type_for_block);
	multi_type_init(&proof->claim_public_type, proof, &_claim_public_type_for_block);
	multi_type_init(&proof->response_type, proof, &_response_type_for_block);
	proof->num_secret = 0;
	proof->num_public = 0;
	element_init(proof->g, G); element_set(proof->g, g);
	element_init(proof->h, G); element_set(proof->h, h);
	
	proof->first_computation = NULL;
	proof->last_computation = NULL;
	proof->first_block = NULL;
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

var_t var_secret_for(proof_t proof, var_t var) {
	if (var_is_secret(var)) {
		return var;
	} else {
		var_t mirror = var_secret(proof);
		computation_mov(proof, mirror, var);
		block_equals_public(proof, mirror, var);
		return mirror;
	}
}

void inst_init_prover(proof_t proof, inst_t inst) {
	int i;
	inst->secret_values = pbc_malloc(proof->num_secret * sizeof(element_t));
	inst->secret_openings = pbc_malloc(proof->num_secret * sizeof(element_t));
	inst->secret_commitments = pbc_malloc(proof->num_secret * sizeof(element_t));
	inst->public_values = pbc_malloc(proof->num_public * sizeof(element_t));
	inst->supplement_data = new((type_ptr)&proof->supplement_type);
	for (i = 0; i < proof->num_secret; i++) {
		element_init(inst->secret_values[i], proof->Z_type->field);
		element_init(inst->secret_openings[i], proof->Z_type->field);
		element_init(inst->secret_commitments[i], proof->G_type->field);
	}
	for (i = 0; i < proof->num_public; i++) {
		element_init(inst->public_values[i], proof->Z_type->field);
	}
	
}

void inst_init_verifier(proof_t proof, inst_t inst) {
	int i;
	inst->secret_values = NULL;
	inst->secret_openings = NULL;
	inst->secret_commitments = pbc_malloc(proof->num_secret * sizeof(element_t));
	inst->public_values = pbc_malloc(proof->num_public * sizeof(element_t));
	inst->supplement_data = new((type_ptr)&proof->supplement_type);
	for (i = 0; i < proof->num_secret; i++) {
		element_init(inst->secret_commitments[i], proof->G_type->field);
	}
	for (i = 0; i < proof->num_public; i++) {
		element_init(inst->public_values[i], proof->Z_type->field);
	}
}

void inst_clear(proof_t proof, inst_t inst) {
	int i;
	if (inst->secret_values != NULL) {
		for (i = 0; i < proof->num_secret; i++) {
			element_clear(inst->secret_values[i]);
			element_clear(inst->secret_openings[i]);
			element_clear(inst->secret_commitments[i]);
		}
		pbc_free(inst->secret_values);
		pbc_free(inst->secret_openings);
	} else {
		for (i = 0; i < proof->num_secret; i++) {
			element_clear(inst->secret_commitments[i]);
		}
	}
	pbc_free(inst->secret_commitments);
	
	for (i = 0; i < proof->num_public; i++) {
		element_clear(inst->public_values[i]);
	}
	pbc_free(inst->public_values);
	delete((type_ptr)&proof->supplement_type, inst->supplement_data);
}

void update_secret_commitment(proof_t proof, inst_t inst, long index) {
	element_random(inst->secret_openings[index]);
	element_pow2_zn(inst->secret_commitments[index], // C_x = g^x h^(o_x)
		proof->g, inst->secret_values[index],
		proof->h, inst->secret_openings[index]);
}

void inst_var_set(proof_t proof, inst_t inst, var_t var, element_t value) {
	if (var_is_secret(var)) {
		assert(inst->secret_values != NULL);
		element_set(inst->secret_values[var_index(var)], value);
		update_secret_commitment(proof, inst, var_index(var));
	} else {
		element_set(inst->public_values[var_index(var)], value);
	}
}

void inst_var_set_mpz(proof_t proof, inst_t inst, var_t var, mpz_t value) {
	if (var_is_secret(var)) {
		assert(inst->secret_values != NULL);
		element_set_mpz(inst->secret_values[var_index(var)], value);
		update_secret_commitment(proof, inst, var_index(var));
	} else {
		element_set_mpz(inst->public_values[var_index(var)], value);
	}
}

void inst_var_set_si(proof_t proof, inst_t inst, var_t var, long int value) {
	if (var_is_secret(var)) {
		assert(inst->secret_values != NULL);
		element_set_si(inst->secret_values[var_index(var)], value);
		update_secret_commitment(proof, inst, var_index(var));
	} else {
		element_set_si(inst->public_values[var_index(var)], value);
	}
}

element_ptr inst_var_get(proof_t proof, inst_t inst, var_t var) {
	if (var_is_secret(var)) {
		assert(inst->secret_values != NULL);
		return inst->secret_values[var_index(var)];
	} else return inst->public_values[var_index(var)];
}

void inst_var_write(proof_t proof, inst_t inst, var_t var, FILE* stream) {
	element_write(proof->Z_type->field, inst_var_get(proof, inst, var), stream);
}

void inst_var_read(proof_t proof, inst_t inst, var_t var, FILE* stream) {
	if (var_is_secret(var)) {
		assert(inst->secret_values != NULL);
		element_read(proof->Z_type->field, inst->secret_values[var_index(var)], stream);
		update_secret_commitment(proof, inst, var_index(var));
	} else {
		element_read(proof->Z_type->field, inst->public_values[var_index(var)], stream);
	}
}

data_ptr inst_supplement(proof_t proof, inst_t inst, supplement_t supplement) {
	return (data_ptr)((char*)inst->supplement_data + supplement);
}

void inst_commitments_write(proof_t proof, inst_t inst, FILE* stream) {
	int i;
	for (i = 0; i < proof->num_secret; i++) {
		element_write(proof->G_type->field, inst->secret_commitments[i], stream);
	}
}

void inst_commitments_read(proof_t proof, inst_t inst, FILE* stream) {
	int i;
	for (i = 0; i < proof->num_secret; i++) {
		element_read(proof->G_type->field, inst->secret_commitments[i], stream);
	}
}
