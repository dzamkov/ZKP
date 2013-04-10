#include <assert.h>
#include <stdarg.h>
#include "zkp.h"
#include "zkp_internal.h"

void block_insert(proof_t proof, struct block_s *block) {
	block->next = proof->first_block;
	proof->first_block = block;
	proof->witness_size += block->witness_size;
}

void blocks_clear(proof_t proof) {
	struct block_s* current = proof->first_block;
	while (current != NULL) {
		current->clear(current);
		current = current->next;
	}
}

void witness_init(proof_t proof, witness_t witness) {
	struct block_s* current = proof->first_block;
	void* current_witness;
	current_witness = *witness = pbc_malloc(proof->witness_size);
	while (current != NULL) {
		current->witness_init(current, proof, current_witness);
		current_witness = (void*)((unsigned char*)current_witness + current->witness_size);
		current = current->next;
	}
}

void witness_clear(proof_t proof, witness_t witness) {
	struct block_s* current = proof->first_block;
	void* current_witness = *witness;
	while (current != NULL) {
		current->witness_clear(current, current_witness);
		current_witness = (void*)((unsigned char*)current_witness + current->witness_size);
		current = current->next;
	}
	pbc_free(*witness);
}

void witness_claim_gen(proof_t proof, inst_t inst, witness_t witness) {
	struct block_s* current = proof->first_block;
	void* current_witness = *witness;
	while (current != NULL) {
		current->witness_claim_gen(current, current_witness, proof, inst);
		current_witness = (void*)((unsigned char*)current_witness + current->witness_size);
		current = current->next;
	}
}

void witness_claim_write(proof_t proof, witness_t witness, FILE* stream) {
	struct block_s* current = proof->first_block;
	void* current_witness = *witness;
	while (current != NULL) {
		current->witness_claim_write(current, current_witness, stream);
		current_witness = (void*)((unsigned char*)current_witness + current->witness_size);
		current = current->next;
	}
}

void witness_claim_read(proof_t proof, witness_t witness, FILE* stream) {
	struct block_s* current = proof->first_block;
	void* current_witness = *witness;
	while (current != NULL) {
		current->witness_claim_read(current, current_witness, stream);
		current_witness = (void*)((unsigned char*)current_witness + current->witness_size);
		current = current->next;
	}
}

void witness_response_gen(proof_t proof, inst_t inst, witness_t witness, challenge_t challenge) {
	struct block_s* current = proof->first_block;
	void* current_witness = *witness;
	while (current != NULL) {
		current->witness_response_gen(current, current_witness, proof, inst, challenge);
		current_witness = (void*)((unsigned char*)current_witness + current->witness_size);
		current = current->next;
	}
}

void witness_response_write(proof_t proof, witness_t witness, FILE* stream) {
	struct block_s* current = proof->first_block;
	void* current_witness = *witness;
	while (current != NULL) {
		current->witness_response_write(current, current_witness, stream);
		current_witness = (void*)((unsigned char*)current_witness + current->witness_size);
		current = current->next;
	}
}

void witness_response_read(proof_t proof, witness_t witness, FILE* stream) {
	struct block_s* current = proof->first_block;
	void* current_witness = *witness;
	while (current != NULL) {
		current->witness_response_read(current, current_witness, stream);
		current_witness = (void*)((unsigned char*)current_witness + current->witness_size);
		current = current->next;
	}
}

int witness_response_verify(proof_t proof, inst_t inst, witness_t witness, challenge_t challenge) {
	struct block_s* current = proof->first_block;
	void* current_witness = *witness;
	while (current != NULL) {
		if (!current->witness_response_verify(current, current_witness, proof, inst, challenge))
			return 0;
		current_witness = (void*)((unsigned char*)current_witness + current->witness_size);
		current = current->next;
	}
	return 1;
}

// Contains witness information for a secret variable. 
struct var_witness_s {
	element_t randomizer_value;
	element_t randomizer_opening;
	element_t randomizer_commitment;
	element_t boxed_value;
	element_t boxed_opening;
};
typedef struct var_witness_s var_witness_t[1];

// Variable Notation:
// X 		= inst->secret_values[X_index]
// o_X 		= inst->secret_openings[X_index]
// C_X		= inst->secret_commitments[X_index]
// r_X		= X_witness->randomizer_value
// r_o_X	= X_witness->randomizer_opening
// r_C_X	= X_witness->randomizer_commitment
// [X]		= X_witness->boxed_value
// [o_X]	= X_witness->boxed_opening
// e		= challenge

// Necessary Relationships:
// C_X                	= (g ^ X)(h ^ o_X)
// r_C_X              	= (g ^ r_X)(h ^ r_o_X)
// [X]                	= eX + r_X
// [o_X]              	= e(o_X) + r_o_X
// (C_X) ^ e * (r_C_X)	= (g ^ [X])(h ^ [o_X])

void var_witness_init(proof_t proof, var_witness_t witness) {
	element_init(witness->randomizer_value, proof->Z);
	element_init(witness->randomizer_opening, proof->Z);
	element_init(witness->randomizer_commitment, proof->G);
	element_init(witness->boxed_value, proof->Z);
	element_init(witness->boxed_opening, proof->Z);
}

void var_witness_clear(var_witness_t witness) {
	element_clear(witness->randomizer_value);
	element_clear(witness->randomizer_opening);
	element_clear(witness->randomizer_commitment);
	element_clear(witness->boxed_value);
	element_clear(witness->boxed_opening);
}

void var_witness_claim_gen(proof_t proof, var_witness_t witness) {
	element_random(witness->randomizer_value);
	element_random(witness->randomizer_opening);
	element_pow2_zn(witness->randomizer_commitment,
		proof->g, witness->randomizer_value,
		proof->h, witness->randomizer_opening);
}

void var_witness_claim_write(var_witness_t witness, FILE* stream) {
	element_out_raw(stream, witness->randomizer_commitment);
}

void var_witness_claim_read(var_witness_t witness, FILE* stream) {
	element_inp_raw(witness->randomizer_commitment, stream);
}

void var_witness_response_gen(proof_t proof, var_witness_t witness, challenge_t challenge, element_t value, element_t opening) {
	element_mul(witness->boxed_value, challenge, value);
	element_add(witness->boxed_value, witness->boxed_value, witness->randomizer_value);
	element_mul(witness->boxed_opening, challenge, opening);
	element_add(witness->boxed_opening, witness->boxed_opening, witness->randomizer_opening);
}

void var_witness_response_write(var_witness_t witness, FILE* stream) {
	element_out_raw(stream, witness->boxed_value);
	element_out_raw(stream, witness->boxed_opening);
}

void var_witness_response_read(var_witness_t witness, FILE* stream) {
	element_inp_raw(witness->boxed_value, stream);
	element_inp_raw(witness->boxed_opening, stream);
}

int var_witness_response_verify(proof_t proof, var_witness_t witness, challenge_t challenge, element_t commitment) {
	element_t left; element_init(left, proof->G);
	element_t right; element_init(right, proof->G);
	
	element_pow_zn(left, commitment, challenge);
	element_mul(left, left, witness->randomizer_commitment);
	element_pow2_zn(right, proof->g, witness->boxed_value, proof->h, witness->boxed_opening);
	int result = !element_cmp(left, right);
	
	element_clear(left);
	element_clear(right);
	return result;
}

/***************************************************
* equals_public
*
* Verifies that a secret variable is equivalent to
* a public variable.
****************************************************/

struct block_equals_public_s {
	struct block_s base;
	long secret_index;
	long public_index;
};

struct block_equals_public_witness_s {
	var_witness_t secret; // S
};

// r_S	= 0
// [S]	= eP

void equals_public_clear(struct block_s* block) {
	struct block_equals_public_s *self = (struct block_equals_public_s*)block;
	pbc_free(self);
}

void equals_public_witness_init(struct block_s* block, proof_t proof, void* witness) {
	struct block_equals_public_witness_s *self_witness = (struct block_equals_public_witness_s*)witness;
	var_witness_init(proof, self_witness->secret);
}

void equals_public_witness_clear(struct block_s* block, void* witness) {
	struct block_equals_public_witness_s *self_witness = (struct block_equals_public_witness_s*)witness;
	var_witness_clear(self_witness->secret);
}

void equals_public_witness_claim_gen(struct block_s* block, void* witness, proof_t proof, inst_t inst) {
	struct block_equals_public_witness_s *self_witness = (struct block_equals_public_witness_s*)witness;
	element_set0(self_witness->secret->randomizer_value);
	element_random(self_witness->secret->randomizer_opening);
	element_pow_zn(self_witness->secret->randomizer_commitment, proof->h, self_witness->secret->randomizer_opening);
}

void equals_public_witness_claim_write(struct block_s* block, void* witness, FILE* stream) {
	struct block_equals_public_witness_s *self_witness = (struct block_equals_public_witness_s*)witness;
	var_witness_claim_write(self_witness->secret, stream);
}

void equals_public_witness_claim_read(struct block_s* block, void* witness, FILE* stream) {
	struct block_equals_public_witness_s *self_witness = (struct block_equals_public_witness_s*)witness;
	var_witness_claim_read(self_witness->secret, stream);
}

void equals_public_witness_response_gen(struct block_s* block, void* witness, proof_t proof, inst_t inst, challenge_t challenge) {
	struct block_equals_public_s *self = (struct block_equals_public_s*)block;
	struct block_equals_public_witness_s *self_witness = (struct block_equals_public_witness_s*)witness;
	var_witness_response_gen(proof, self_witness->secret, challenge, inst->secret_values[self->secret_index], inst->secret_openings[self->secret_index]);
}

void equals_public_witness_response_write(struct block_s* block, void* witness, FILE* stream) {
	struct block_equals_public_witness_s *self_witness = (struct block_equals_public_witness_s*)witness;
	var_witness_response_write(self_witness->secret, stream);
}

void equals_public_witness_response_read(struct block_s* block, void* witness, FILE* stream) {
	struct block_equals_public_witness_s *self_witness = (struct block_equals_public_witness_s*)witness;
	var_witness_response_read(self_witness->secret, stream);
}

int equals_public_witness_response_verify(struct block_s* block, void* witness, proof_t proof, inst_t inst, challenge_t challenge) {
	struct block_equals_public_s *self = (struct block_equals_public_s*)block;
	struct block_equals_public_witness_s *self_witness = (struct block_equals_public_witness_s*)witness;
	if (var_witness_response_verify(proof, self_witness->secret, challenge, inst->secret_commitments[self->secret_index])) {
		element_t right; element_init(right, proof->Z);
		element_mul(right, challenge, inst->public_values[self->public_index]);
		int result = !element_cmp(self_witness->secret->boxed_value, right);
		element_clear(right);
		return result;
	} else return 0;
}

void block_equals_public(proof_t proof, var_t secret, var_t _public) {
	struct block_equals_public_s *self = (struct block_equals_public_s*)pbc_malloc(sizeof(struct block_equals_public_s));
	self->base.clear = &equals_public_clear;
	self->base.witness_init = &equals_public_witness_init;
	self->base.witness_clear = &equals_public_witness_clear;
	self->base.witness_claim_gen = &equals_public_witness_claim_gen;
	self->base.witness_claim_write = &equals_public_witness_claim_write;
	self->base.witness_claim_read = &equals_public_witness_claim_read;
	self->base.witness_response_gen = &equals_public_witness_response_gen;
	self->base.witness_response_write = &equals_public_witness_response_write;
	self->base.witness_response_read = &equals_public_witness_response_read;
	self->base.witness_response_verify = &equals_public_witness_response_verify;
	self->base.witness_size = sizeof(struct block_equals_public_witness_s);
	self->secret_index = var_index(secret);
	self->public_index = var_index(_public);
	block_insert(proof, &self->base);
}

/***************************************************
* equals
*
* Verifies that a set of secret variables are
* equivalent.
****************************************************/

struct block_equals_s {
	struct block_s base;
	int count;
	long *indices;
};

// r_S_1	= r_S_2		= ...		= r_S_n
// [S_1]	= [S_2]		= ...		= [S_n]

void equals_clear(struct block_s* block) {
	struct block_equals_s *self = (struct block_equals_s*)block;
	pbc_free(self);
}

void equals_witness_init(struct block_s* block, proof_t proof, void* witness) {
	int i;
	struct block_equals_s *self = (struct block_equals_s*)block;
	var_witness_t* self_witness = (var_witness_t*)witness;
	for (i = 0; i < self->count; i++) {
		var_witness_init(proof, self_witness[i]);
	}
}

void equals_witness_clear(struct block_s* block, void* witness) {
	int i;
	struct block_equals_s *self = (struct block_equals_s*)block;
	var_witness_t* self_witness = (var_witness_t*)witness;
	for (i = 0; i < self->count; i++) {
		var_witness_clear(self_witness[i]);
	}
}

void equals_witness_claim_gen(struct block_s* block, void* witness, proof_t proof, inst_t inst) {
	int i;
	struct block_equals_s *self = (struct block_equals_s*)block;
	var_witness_t* self_witness = (var_witness_t*)witness;
	element_t randomizer_value; element_init(randomizer_value, proof->Z);
	element_random(randomizer_value);
	for (i = 0; i < self->count; i++) {
		element_set(self_witness[i]->randomizer_value, randomizer_value);
		element_random(self_witness[i]->randomizer_opening);
		element_pow2_zn(self_witness[i]->randomizer_commitment,
			proof->g, self_witness[i]->randomizer_value,
			proof->h, self_witness[i]->randomizer_opening);
	}
	element_clear(randomizer_value);
}

void equals_witness_claim_write(struct block_s* block, void* witness, FILE* stream) {
	int i;
	struct block_equals_s *self = (struct block_equals_s*)block;
	var_witness_t* self_witness = (var_witness_t*)witness;
	for (i = 0; i < self->count; i++) {
		var_witness_claim_write(self_witness[i], stream);
	}
}

void equals_witness_claim_read(struct block_s* block, void* witness, FILE* stream) {
	int i;
	struct block_equals_s *self = (struct block_equals_s*)block;
	var_witness_t* self_witness = (var_witness_t*)witness;
	for (i = 0; i < self->count; i++) {
		var_witness_claim_read(self_witness[i], stream);
	}
}

void equals_witness_response_gen(struct block_s* block, void* witness, proof_t proof, inst_t inst, challenge_t challenge) {
	int i;
	struct block_equals_s *self = (struct block_equals_s*)block;
	var_witness_t* self_witness = (var_witness_t*)witness;
	for (i = 0; i < self->count; i++) {
		long index = self->indices[i];
		var_witness_response_gen(proof, self_witness[i], challenge, inst->secret_values[index], inst->secret_openings[index]);
	}
}

void equals_witness_response_write(struct block_s* block, void* witness, FILE* stream) {
	int i;
	struct block_equals_s *self = (struct block_equals_s*)block;
	var_witness_t* self_witness = (var_witness_t*)witness;
	for (i = 0; i < self->count; i++) {
		var_witness_response_write(self_witness[i], stream);
	}
}

void equals_witness_response_read(struct block_s* block, void* witness, FILE* stream) {
	int i;
	struct block_equals_s *self = (struct block_equals_s*)block;
	var_witness_t* self_witness = (var_witness_t*)witness;
	for (i = 0; i < self->count; i++) {
		var_witness_response_read(self_witness[i], stream);
	}
}

int equals_witness_response_verify(struct block_s* block, void* witness, proof_t proof, inst_t inst, challenge_t challenge) {
	int i;
	struct block_equals_s *self = (struct block_equals_s*)block;
	var_witness_t* self_witness = (var_witness_t*)witness;
	for (i = 0; i < self->count; i++)
		if (!var_witness_response_verify(proof, self_witness[i], challenge, inst->secret_commitments[self->indices[i]]))
			return 0;
	for (i = 1; i < self->count; i++)
		if (element_cmp(self_witness[i - 1]->boxed_value, self_witness[i]->boxed_value))
			return 0;
	return 1;
}

struct block_equals_s* block_equals_base(proof_t proof, int count) {
	struct block_equals_s *self = (struct block_equals_s*)pbc_malloc(sizeof(struct block_equals_s));
	self->base.clear = &equals_clear;
	self->base.witness_init = &equals_witness_init;
	self->base.witness_clear = &equals_witness_clear;
	self->base.witness_claim_gen = &equals_witness_claim_gen;
	self->base.witness_claim_write = &equals_witness_claim_write;
	self->base.witness_claim_read = &equals_witness_claim_read;
	self->base.witness_response_gen = &equals_witness_response_gen;
	self->base.witness_response_write = &equals_witness_response_write;
	self->base.witness_response_read = &equals_witness_response_read;
	self->base.witness_response_verify = &equals_witness_response_verify;
	self->base.witness_size = sizeof(var_witness_t) * count;
	self->count = count;
	self->indices = (long*)pbc_malloc(sizeof(long) * count);
	block_insert(proof, &self->base);
	return self;
}

void require_equal(proof_t proof, int count, ...) {
	int i;
	struct block_equals_s *self = block_equals_base(proof, count);
	va_list argp;
	va_start(argp, count);
	for (i = 0; i < count; i++) self->indices[i] = var_secret_for(proof, va_arg(argp, var_t));
	va_end(argp);
}

void require_equal_2(proof_t proof, var_t a, var_t b) {
	struct block_equals_s *self = block_equals_base(proof, 2);
	self->indices[0] = var_secret_for(proof, a);
	self->indices[1] = var_secret_for(proof, b);
}

void require_equal_3(proof_t proof, var_t a, var_t b, var_t c) {
	struct block_equals_s *self = block_equals_base(proof, 3);
	self->indices[0] = var_secret_for(proof, a);
	self->indices[1] = var_secret_for(proof, b);
	self->indices[2] = var_secret_for(proof, c);
}

void require_equal_many(proof_t proof, int count, var_t* vars) {
	int i;
	struct block_equals_s *self = block_equals_base(proof, count);
	for (i = 0; i < count; i++) self->indices[i] = var_secret_for(proof, vars[i]);
}

/***************************************************
* wsum_zero
*
* Verifies that the sum of a set of terms (product
* of a secret variable and a constant) is zero.
****************************************************/

struct block_wsum_zero_s {
	struct block_s base;
	int count;
	long* indices;
	long* coefficients;
};

// k	= (c_1)(r_S_1) 	+ (c_2)(r_S_2)	+ ...	+ (c_n)(r_S_n)
// k	= (c_1)[S_1]  	+ (c_2)[S_2]  	+ ...	+ (c_n)[S_n]  

void wsum_zero_clear(struct block_s* block) {
	struct block_wsum_zero_s *self = (struct block_wsum_zero_s*)block;
	pbc_free(self);
}

void wsum_zero_witness_init(struct block_s* block, proof_t proof, void* witness) {
	int i;
	struct block_wsum_zero_s *self = (struct block_wsum_zero_s*)block;
	var_witness_t* self_witness = (var_witness_t*)witness;
	element_ptr k = (element_ptr)(self_witness + self->count);
	element_init(k, proof->Z);
	for (i = 0; i < self->count; i++) {
		var_witness_init(proof, self_witness[i]);
	}
}

void wsum_zero_witness_clear(struct block_s* block, void* witness) {
	int i;
	struct block_wsum_zero_s *self = (struct block_wsum_zero_s*)block;
	var_witness_t* self_witness = (var_witness_t*)witness;
	element_ptr k = (element_ptr)(self_witness + self->count);
	element_clear(k);
	for (i = 0; i < self->count; i++) {
		var_witness_clear(self_witness[i]);
	}
}

void wsum_zero_witness_claim_gen(struct block_s* block, void* witness, proof_t proof, inst_t inst) {
	int i;
	struct block_wsum_zero_s *self = (struct block_wsum_zero_s*)block;
	var_witness_t* self_witness = (var_witness_t*)witness;
	element_ptr k = (element_ptr)(self_witness + self->count);
	element_t temp; element_init(temp, proof->Z);
	for (i = 0; i < self->count; i++) {
		var_witness_claim_gen(proof, self_witness[i]);
		long coefficient = self->coefficients[i];
		if (coefficient == 1) 
			element_add(k, k, self_witness[i]->randomizer_value);
		else if (coefficient == -1) 
			element_sub(k, k, self_witness[i]->randomizer_value);
		else {
			element_mul_si(temp, self_witness[i]->randomizer_value, coefficient);
			element_add(k, k, temp);
		}
	}
	element_clear(temp);
}

void wsum_zero_witness_claim_write(struct block_s* block, void* witness, FILE* stream) {
	int i;
	struct block_wsum_zero_s *self = (struct block_wsum_zero_s*)block;
	var_witness_t* self_witness = (var_witness_t*)witness;
	element_ptr k = (element_ptr)(self_witness + self->count);
	element_out_raw(stream, k);
	for (i = 0; i < self->count; i++) {
		var_witness_claim_write(self_witness[i], stream);
	}
}

void wsum_zero_witness_claim_read(struct block_s* block, void* witness, FILE* stream) {
	int i;
	struct block_wsum_zero_s *self = (struct block_wsum_zero_s*)block;
	var_witness_t* self_witness = (var_witness_t*)witness;
	element_ptr k = (element_ptr)(self_witness + self->count);
	element_inp_raw(k, stream);
	for (i = 0; i < self->count; i++) {
		var_witness_claim_read(self_witness[i], stream);
	}
}

void wsum_zero_witness_response_gen(struct block_s* block, void* witness, proof_t proof, inst_t inst, challenge_t challenge) {
	int i;
	struct block_wsum_zero_s *self = (struct block_wsum_zero_s*)block;
	var_witness_t* self_witness = (var_witness_t*)witness;
	for (i = 0; i < self->count; i++) {
		long index = self->indices[i];
		var_witness_response_gen(proof, self_witness[i], challenge, inst->secret_values[index], inst->secret_openings[index]);
	}
}

void wsum_zero_witness_response_write(struct block_s* block, void* witness, FILE* stream) {
	int i;
	struct block_wsum_zero_s *self = (struct block_wsum_zero_s*)block;
	var_witness_t* self_witness = (var_witness_t*)witness;
	for (i = 0; i < self->count; i++) {
		var_witness_response_write(self_witness[i], stream);
	}
}

void wsum_zero_witness_response_read(struct block_s* block, void* witness, FILE* stream) {
	int i;
	struct block_wsum_zero_s *self = (struct block_wsum_zero_s*)block;
	var_witness_t* self_witness = (var_witness_t*)witness;
	for (i = 0; i < self->count; i++) {
		var_witness_response_read(self_witness[i], stream);
	}
}

int wsum_zero_witness_response_verify(struct block_s* block, void* witness, proof_t proof, inst_t inst, challenge_t challenge) {
	int i;
	struct block_wsum_zero_s *self = (struct block_wsum_zero_s*)block;
	var_witness_t* self_witness = (var_witness_t*)witness;
	element_ptr k = (element_ptr)(self_witness + self->count);
	element_t temp; element_init(temp, proof->Z);
	element_t sum; element_init(sum, proof->Z);
	for (i = 0; i < self->count; i++) {
		if (!var_witness_response_verify(proof, self_witness[i], challenge, inst->secret_commitments[self->indices[i]]))
			return 0;
		long coefficient = self->coefficients[i];
		if (coefficient == 1) 
			element_add(sum, sum, self_witness[i]->boxed_value);
		else if (coefficient == -1) 
			element_sub(sum, sum, self_witness[i]->boxed_value);
		else {
			element_mul_si(temp, self_witness[i]->boxed_value, coefficient);
			element_add(sum, sum, temp);
		}
	}
	return !element_cmp(k, sum);
}

struct block_wsum_zero_s* block_wsum_zero_base(proof_t proof, int count) {
	struct block_wsum_zero_s *self = (struct block_wsum_zero_s*)pbc_malloc(sizeof(struct block_wsum_zero_s));
	self->base.clear = &wsum_zero_clear;
	self->base.witness_init = &wsum_zero_witness_init;
	self->base.witness_clear = &wsum_zero_witness_clear;
	self->base.witness_claim_gen = &wsum_zero_witness_claim_gen;
	self->base.witness_claim_write = &wsum_zero_witness_claim_write;
	self->base.witness_claim_read = &wsum_zero_witness_claim_read;
	self->base.witness_response_gen = &wsum_zero_witness_response_gen;
	self->base.witness_response_write = &wsum_zero_witness_response_write;
	self->base.witness_response_read = &wsum_zero_witness_response_read;
	self->base.witness_response_verify = &wsum_zero_witness_response_verify;
	self->base.witness_size = sizeof(var_witness_t) * count + sizeof(element_t);
	self->count = count;
	self->indices = (long*)pbc_malloc(sizeof(long) * count);
	self->coefficients = (long*)pbc_malloc(sizeof(long) * count);
	block_insert(proof, &self->base);
	return self;
}

void require_sum(proof_t proof, var_t sum, var_t addend_1, var_t addend_2) {
	struct block_wsum_zero_s *self = block_wsum_zero_base(proof, 3);
	self->coefficients[0] = -1; self->indices[0] = var_secret_for(proof, sum);
	self->coefficients[1] = 1; self->indices[1] = var_secret_for(proof, addend_1);
	self->coefficients[2] = 1; self->indices[2] = var_secret_for(proof, addend_2);
}

void require_dif(proof_t proof, var_t dif, var_t minuend, var_t subtrahend) {
	struct block_wsum_zero_s *self = block_wsum_zero_base(proof, 3);
	self->coefficients[0] = -1; self->indices[0] = var_secret_for(proof, dif);
	self->coefficients[1] = 1; self->indices[1] = var_secret_for(proof, minuend);
	self->coefficients[2] = -1; self->indices[2] = var_secret_for(proof, subtrahend);
}

void require_wsum_zero(proof_t proof, int count, ...) {
	int i;
	struct block_wsum_zero_s *self = block_wsum_zero_base(proof, count);
	va_list argp;
	va_start(argp, count);
	for (i = 0; i < count; i++) {
		self->coefficients[i] = va_arg(argp, long);
		self->indices[i] = var_secret_for(proof, va_arg(argp, var_t));
	}
	va_end(argp);
}

void require_wsum_zero_2(proof_t proof, long a_coeff, var_t a, long b_coeff, var_t b) {
	struct block_wsum_zero_s *self = block_wsum_zero_base(proof, 2);
	self->coefficients[0] = a_coeff; self->indices[0] = var_secret_for(proof, a);
	self->coefficients[1] = b_coeff; self->indices[1] = var_secret_for(proof, b);
}

void require_wsum_zero_3(proof_t proof, long a_coeff, var_t a, long b_coeff, var_t b, long c_coeff, var_t c) {
	struct block_wsum_zero_s *self = block_wsum_zero_base(proof, 3);
	self->coefficients[0] = a_coeff; self->indices[0] = var_secret_for(proof, a);
	self->coefficients[1] = b_coeff; self->indices[1] = var_secret_for(proof, b);
	self->coefficients[2] = c_coeff; self->indices[2] = var_secret_for(proof, c);
}

void require_wsum_zero_many(proof_t proof, int count, long* coeffs, var_t* vars) {
	int i;
	struct block_wsum_zero_s *self = block_wsum_zero_base(proof, count);
	for (i = 0; i < count; i++) {
		self->coefficients[i] = coeffs[i];
		self->indices[i] = var_secret_for(proof, vars[i]);
	}
}

/***************************************************
* product
*
* Verifies that the product of two secret variables
* is equivalent to a third.
****************************************************/

struct block_product_s {
	struct block_s base;
	long factor_1_index;
	long factor_2_index;
	long product_index;
};

struct block_product_witness_s {
	var_witness_t factor_1;	// F_1
	var_witness_t factor_2;	// F_2
	var_witness_t product;	// P
	element_t k;
};

// k       	= r_F_1 * r_F_2
// r_P     	= r_F_1 * F_2 + r_F_2 * F_1
// e[P] + k	= [F_1][F_2]

void product_clear(struct block_s* block) {
	struct block_product_s *self = (struct block_product_s*)block;
	pbc_free(self);
}

void product_witness_init(struct block_s* block, proof_t proof, void* witness) {
	struct block_product_witness_s *self_witness = (struct block_product_witness_s*)witness;
	var_witness_init(proof, self_witness->factor_1);
	var_witness_init(proof, self_witness->factor_2);
	var_witness_init(proof, self_witness->product);
	element_init(self_witness->k, proof->Z);
}

void product_witness_clear(struct block_s* block, void* witness) {
	struct block_product_witness_s *self_witness = (struct block_product_witness_s*)witness;
	var_witness_clear(self_witness->factor_1);
	var_witness_clear(self_witness->factor_2);
	var_witness_clear(self_witness->product);
	element_clear(self_witness->k);
}

void product_witness_claim_gen(struct block_s* block, void* witness, proof_t proof, inst_t inst) {
	struct block_product_s *self = (struct block_product_s*)block;
	struct block_product_witness_s *self_witness = (struct block_product_witness_s*)witness;
	var_witness_claim_gen(proof, self_witness->factor_1);
	var_witness_claim_gen(proof, self_witness->factor_2);
	element_t temp; element_init(temp, proof->Z);
	element_mul(self_witness->product->randomizer_value, self_witness->factor_1->randomizer_value, inst->secret_values[self->factor_2_index]);
	element_mul(temp, self_witness->factor_2->randomizer_value, inst->secret_values[self->factor_1_index]);
	element_add(self_witness->product->randomizer_value, self_witness->product->randomizer_value, temp);
	element_random(self_witness->product->randomizer_opening);
	element_pow2_zn(self_witness->product->randomizer_commitment,
		proof->g, self_witness->product->randomizer_value,
		proof->h, self_witness->product->randomizer_opening);
	element_mul(self_witness->k, self_witness->factor_1->randomizer_value, self_witness->factor_2->randomizer_value);
	element_clear(temp);
}

void product_witness_claim_write(struct block_s* block, void* witness, FILE* stream) {
	struct block_product_witness_s *self_witness = (struct block_product_witness_s*)witness;
	var_witness_claim_write(self_witness->factor_1, stream);
	var_witness_claim_write(self_witness->factor_2, stream);
	var_witness_claim_write(self_witness->product, stream);
	element_out_raw(stream, self_witness->k);
}

void product_witness_claim_read(struct block_s* block, void* witness, FILE* stream) {
	struct block_product_witness_s *self_witness = (struct block_product_witness_s*)witness;
	var_witness_claim_read(self_witness->factor_1, stream);
	var_witness_claim_read(self_witness->factor_2, stream);
	var_witness_claim_read(self_witness->product, stream);
	element_inp_raw(self_witness->k, stream);
}

void product_witness_response_gen(struct block_s* block, void* witness, proof_t proof, inst_t inst, challenge_t challenge) {
	struct block_product_s *self = (struct block_product_s*)block;
	struct block_product_witness_s *self_witness = (struct block_product_witness_s*)witness;
	var_witness_response_gen(proof, self_witness->factor_1, challenge, inst->secret_values[self->factor_1_index], inst->secret_openings[self->factor_1_index]);
	var_witness_response_gen(proof, self_witness->factor_2, challenge, inst->secret_values[self->factor_2_index], inst->secret_openings[self->factor_2_index]);
	var_witness_response_gen(proof, self_witness->product, challenge, inst->secret_values[self->product_index], inst->secret_openings[self->product_index]);
}

void product_witness_response_write(struct block_s* block, void* witness, FILE* stream) {
	struct block_product_witness_s *self_witness = (struct block_product_witness_s*)witness;
	var_witness_response_write(self_witness->factor_1, stream);
	var_witness_response_write(self_witness->factor_2, stream);
	var_witness_response_write(self_witness->product, stream);
}

void product_witness_response_read(struct block_s* block, void* witness, FILE* stream) {
	struct block_product_witness_s *self_witness = (struct block_product_witness_s*)witness;
	var_witness_response_read(self_witness->factor_1, stream);
	var_witness_response_read(self_witness->factor_2, stream);
	var_witness_response_read(self_witness->product, stream);
}

int product_witness_response_verify(struct block_s* block, void* witness, proof_t proof, inst_t inst, challenge_t challenge) {
	struct block_product_s *self = (struct block_product_s*)block;
	struct block_product_witness_s *self_witness = (struct block_product_witness_s*)witness;
	if (var_witness_response_verify(proof, self_witness->factor_1, challenge, inst->secret_commitments[self->factor_1_index]) &&
	    var_witness_response_verify(proof, self_witness->factor_2, challenge, inst->secret_commitments[self->factor_2_index]) &&
	    var_witness_response_verify(proof, self_witness->product, challenge, inst->secret_commitments[self->product_index]))
	{
		element_t left; element_init(left, proof->Z);
		element_t right; element_init(right, proof->Z);
		element_mul(left, challenge, self_witness->product->boxed_value);
		element_add(left, left, self_witness->k);
		element_mul(right, self_witness->factor_1->boxed_value, self_witness->factor_2->boxed_value);
		int result = !element_cmp(left, right);
		element_clear(left);
		element_clear(right);
		return result;
	} else return 0;
}

void block_product(proof_t proof, var_t product, var_t factor_1, var_t factor_2) {
	struct block_product_s *self = (struct block_product_s*)pbc_malloc(sizeof(struct block_product_s));
	self->base.clear = &product_clear;
	self->base.witness_init = &product_witness_init;
	self->base.witness_clear = &product_witness_clear;
	self->base.witness_claim_gen = &product_witness_claim_gen;
	self->base.witness_claim_write = &product_witness_claim_write;
	self->base.witness_claim_read = &product_witness_claim_read;
	self->base.witness_response_gen = &product_witness_response_gen;
	self->base.witness_response_write = &product_witness_response_write;
	self->base.witness_response_read = &product_witness_response_read;
	self->base.witness_response_verify = &product_witness_response_verify;
	self->base.witness_size = sizeof(struct block_product_witness_s);
	self->factor_1_index = var_index(factor_1);
	self->factor_2_index = var_index(factor_2);
	self->product_index = var_index(product);
	block_insert(proof, &self->base);
}

void require_mul(proof_t proof, var_t product, var_t factor_1, var_t factor_2) {
	block_product(proof,
		var_secret_for(proof, product),
		var_secret_for(proof, factor_1),
		var_secret_for(proof, factor_2));
}
