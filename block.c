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
	block->next = NULL;
}

void blocks_clear(proof_t proof) {
	struct block_s* current = proof->first_block;
	while (current != NULL) {
		current->clear(current);
		current = current->next;
	}
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

// F_1  	= inst->secret_values[self->factor_1_index]
// F_2  	= inst->secret_values[self->factor_2_index]
// P    	= inst->secret_values[self->product_index]

// r_F_1	= witness->randomizer_values[self->factor_1_index]
// r_F_2	= witness->randomizer_values[self->factor_2_index]
// r_P		= witness->randomizer_values[self->product_index]

// e		= challenge
// [F_1]	= e(F_1) + r_F_1	= response->boxed_values[self->factor_1_index]
// [F_2]	= e(F_2) + r_F_2	= response->boxed_values[self->factor_2_index]
// [P]		= eP + r_P      	= response->boxed_values[self->product_index]


// f		= (r_F_1)(F_2) + (r_F_2)(F_1) - r_P
// d		= (r_F_1)(r_F_2)

// [F_1][F_2] = (e^2)(F_1)(F_2) + e((r_F_1)(F_2) + (r_F_2)(F_1)) + (r_F_1)(r_F_2)
// [F_1][F_2] = e(e(F_1)(F_2) + (r_F_1)(F_2) + (r_F_2)(F_1)) + d
// [F_1][F_2] = e(eP + (r_F_1)(F_2) + (r_F_2)(F_1)) + d                  if P = (F_1)(F_2)
// [F_1][F_2] = e(eP + r_P + (r_F_1)(F_2) + (r_F_2)(F_1) - r_P) + d      if P = (F_1)(F_2)
// [F_1][F_2] = e(eP + r_P + f) + d                                      if P = (F_1)(F_2)
// [F_1][F_2] = e[P] + ef + d                                            if P = (F_1)(F_2)

void product_clear(struct block_s* block) {
	struct block_product_s *self = (struct block_product_s*)block;
	pbc_free(self);
}

void product_generate(struct block_s* block, proof_t proof, 
		inst_t inst, witness_t witness, FILE* data)
{
	struct block_product_s *self = (struct block_product_s*)block;
	mpz_t f; mpz_init(f);
	mpz_t d; mpz_init(d);
	
	mpz_neg(f, witness->randomizer_values[self->product_index]);
	mpz_addmul(f, witness->randomizer_values[self->factor_1_index], inst->secret_values[self->factor_2_index]);
	mpz_addmul(f, witness->randomizer_values[self->factor_2_index], inst->secret_values[self->factor_1_index]);
	mpz_out_raw(data, f);
	
	mpz_mul(d, witness->randomizer_values[self->factor_1_index], witness->randomizer_values[self->factor_2_index]);
	mpz_out_raw(data, d);
	
	mpz_clear(f);
	mpz_clear(d);
}

int product_verify(struct block_s* block, proof_t proof, inst_t inst, witness_t witness, 
		FILE* data, challenge_t challenge, response_t response)
{
	struct block_product_s *self = (struct block_product_s*)block;
	mpz_t f; mpz_init(f); mpz_inp_raw(f, data);
	mpz_t d; mpz_init(d); mpz_inp_raw(d, data);
	mpz_t check; mpz_init(check);
	
	mpz_set(check, d);
	mpz_addmul(check, challenge, f);
	mpz_addmul(check, challenge, response->boxed_values[self->product_index]);
	mpz_submul(check, response->boxed_values[self->factor_1_index], response->boxed_values[self->factor_2_index]);
	int res = mpz_is0(check);
	
	mpz_clear(f);
	mpz_clear(d);
	mpz_clear(check);
	return res;
}

void block_product(proof_t proof, var_t product, var_t factor_1, var_t factor_2) {
	struct block_product_s *self = (struct block_product_s*)pbc_malloc(sizeof(struct block_product_s));
	self->base.clear = &product_clear;
	self->base.generate = &product_generate;
	self->base.verify = &product_verify;
	block_insert(proof, &self->base);
}
