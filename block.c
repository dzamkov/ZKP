#include <assert.h>
#include "zkp.h"
#include "zkp_internal.h"

void block_insert(proof_t proof, struct block_s *block) {
	if (proof->last_block == NULL) {
		proof->first_block = block;
	} else {
		proof->last_block->next = block;
	}
	proof->last_block = block;
	proof->witness_size += block->witness_size;
	block->next = NULL;
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
	}
}

void witness_clear(proof_t proof, witness_t witness) {
	struct block_s* current = proof->first_block;
	void* current_witness = *witness;
	while (current != NULL) {
		current->witness_clear(current, current_witness);
		current_witness = (void*)((unsigned char*)current_witness + current->witness_size);
	}
	pbc_free(*witness);
}

void witness_claim_gen(proof_t proof, inst_t inst, witness_t witness) {
	struct block_s* current = proof->first_block;
	void* current_witness = *witness;
	while (current != NULL) {
		current->witness_claim_gen(current, current_witness, proof, inst);
		current_witness = (void*)((unsigned char*)current_witness + current->witness_size);
	}
}

void witness_claim_write(proof_t proof, witness_t witness, FILE* stream) {
	struct block_s* current = proof->first_block;
	void* current_witness = *witness;
	while (current != NULL) {
		current->witness_claim_write(current, current_witness, stream);
		current_witness = (void*)((unsigned char*)current_witness + current->witness_size);
	}
}

void witness_claim_read(proof_t proof, witness_t witness, FILE* stream) {
	struct block_s* current = proof->first_block;
	void* current_witness = *witness;
	while (current != NULL) {
		current->witness_claim_read(current, current_witness, stream);
		current_witness = (void*)((unsigned char*)current_witness + current->witness_size);
	}
}

void witness_reponse_gen(proof_t proof, inst_t inst, witness_t witness, challenge_t challenge) {
	struct block_s* current = proof->first_block;
	void* current_witness = *witness;
	while (current != NULL) {
		current->witness_response_gen(current, current_witness, proof, inst, challenge);
		current_witness = (void*)((unsigned char*)current_witness + current->witness_size);
	}
}

void witness_response_write(proof_t proof, witness_t witness, FILE* stream) {
	struct block_s* current = proof->first_block;
	void* current_witness = *witness;
	while (current != NULL) {
		current->witness_response_write(current, current_witness, stream);
		current_witness = (void*)((unsigned char*)current_witness + current->witness_size);
	}
}

void witness_response_read(proof_t proof, witness_t witness, FILE* stream) {
	struct block_s* current = proof->first_block;
	void* current_witness = *witness;
	while (current != NULL) {
		current->witness_response_read(current, current_witness, stream);
		current_witness = (void*)((unsigned char*)current_witness + current->witness_size);
	}
}

int witness_response_verify(proof_t proof, inst_t inst, witness_t witness, challenge_t challenge) {
	struct block_s* current = proof->first_block;
	void* current_witness = *witness;
	while (current != NULL) {
		if (!current->witness_response_verify(current, current_witness, proof, inst, challenge))
			return 0;
		current_witness = (void*)((unsigned char*)current_witness + current->witness_size);
	}
	return 1;
}

// Contains witness information for a secret variable. 
struct var_witness_s {
	mpz_t randomizer_value;
	mpz_t randomizer_opening;
	element_t randomizer_commitment;
	mpz_t boxed_value;
	mpz_t boxed_opening;
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
	mpz_init(witness->randomizer_value);
	mpz_init(witness->randomizer_opening);
	element_init_same_as(witness->randomizer_commitment, proof->g);
}

void var_witness_clear(var_witness_t witness) {
	mpz_clear(witness->randomizer_value);
	mpz_clear(witness->randomizer_opening);
	element_clear(witness->randomizer_commitment);
}

void var_witness_claim_gen(proof_t proof, var_witness_t witness) {
	pbc_mpz_random(witness->randomizer_value, proof->g->field->order);
	pbc_mpz_random(witness->randomizer_opening, proof->g->field->order);
	element_pow2_mpz(witness->randomizer_commitment,
		proof->g, witness->randomizer_value,
		proof->h, witness->randomizer_opening);
}

void var_witness_claim_write(var_witness_t witness, FILE* stream) {
	element_out_raw(stream, witness->randomizer_commitment);
}

void var_witness_claim_read(var_witness_t witness, FILE* stream) {
	element_inp_raw(witness->randomizer_commitment, stream);
}

void var_witness_response_gen(proof_t proof, var_witness_t witness, challenge_t challenge, mpz_t value, mpz_t opening) {
	mpz_mul(witness->boxed_value, challenge, value);
	mpz_add(witness->boxed_value, witness->boxed_value, witness->randomizer_value);
	mpz_mul(witness->boxed_opening, challenge, opening);
	mpz_add(witness->boxed_opening, witness->boxed_opening, witness->randomizer_opening);
}

void var_witness_response_write(var_witness_t witness, FILE* stream) {
	mpz_out_raw(stream, witness->boxed_value);
	mpz_out_raw(stream, witness->boxed_opening);
}

void var_witness_response_read(var_witness_t witness, FILE* stream) {
	mpz_inp_raw(witness->boxed_value, stream);
	mpz_inp_raw(witness->boxed_opening, stream);
}

/***************************************************
* Product
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
	mpz_t k;
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
	mpz_init(self_witness->k);
}

void product_witness_clear(struct block_s* block, void* witness) {
	struct block_product_witness_s *self_witness = (struct block_product_witness_s*)witness;
	var_witness_clear(self_witness->factor_1);
	var_witness_clear(self_witness->factor_2);
	var_witness_clear(self_witness->product);
	mpz_clear(self_witness->k);
}

void product_witness_claim_gen(struct block_s* block, void* witness, proof_t proof, inst_t inst) {
	struct block_product_s *self = (struct block_product_s*)block;
	struct block_product_witness_s *self_witness = (struct block_product_witness_s*)witness;
	var_witness_claim_gen(proof, self_witness->factor_1);
	var_witness_claim_gen(proof, self_witness->factor_2);
	mpz_mul(self_witness->product->randomizer_value, self_witness->factor_1->randomizer_value, inst->secret_values[self->factor_2_index]);
	mpz_addmul(self_witness->product->randomizer_value, self_witness->factor_2->randomizer_value, inst->secret_values[self->factor_1_index]);
	pbc_mpz_random(self_witness->product->randomizer_opening, proof->g->field->order);
	element_pow2_mpz(self_witness->product->randomizer_commitment,
		proof->g, self_witness->product->randomizer_value,
		proof->h, self_witness->product->randomizer_opening);
	mpz_mul(self_witness->k, self_witness->factor_1->randomizer_value, self_witness->factor_2->randomizer_value);
}

void product_witness_claim_write(struct block_s* block, void* witness, FILE* stream) {
	struct block_product_witness_s *self_witness = (struct block_product_witness_s*)witness;
	var_witness_claim_write(self_witness->factor_1, stream);
	var_witness_claim_write(self_witness->factor_2, stream);
	var_witness_claim_write(self_witness->product, stream);
	mpz_out_raw(stream, self_witness->k);
}

void product_witness_claim_read(struct block_s* block, void* witness, FILE* stream) {
	struct block_product_witness_s *self_witness = (struct block_product_witness_s*)witness;
	var_witness_claim_read(self_witness->factor_1, stream);
	var_witness_claim_read(self_witness->factor_2, stream);
	var_witness_claim_read(self_witness->product, stream);
	mpz_inp_raw(self_witness->k, stream);
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
	self->base.witness_size = sizeof(struct block_product_witness_s);
	block_insert(proof, &self->base);
}
