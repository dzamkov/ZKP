#include <assert.h>
#include <stdarg.h>
#include <pbc.h>
#include "zkp_io.h"
#include "zkp_proof.h"
#include "zkp_internal.h"

void block_insert(proof_t proof, block_ptr block) {
	block->next = proof->first_block;
	proof->first_block = block;
	proof->supplement_type.base->size += block->supplement_type->size;
	proof->claim_secret_type.base->size += block->claim_secret_type->size;
	proof->claim_public_type.base->size += block->claim_public_type->size;
	proof->response_type.base->size += block->response_type->size;
}

void blocks_clear(proof_t proof) {
	block_ptr current = proof->first_block;
	while (current != NULL) {
		current->clear(current);
		current = current->next;
	}
}

void claim_gen(proof_t proof, inst_t inst, data_ptr claim_secret, data_ptr claim_public) {
	block_ptr current = proof->first_block;
	while (current != NULL) {
		current->claim_gen(current, proof, inst, claim_secret, claim_public);
		claim_secret = (data_ptr)((char*)claim_secret + current->claim_secret_type->size);
		claim_public = (data_ptr)((char*)claim_public + current->claim_public_type->size);
		current = current->next;
	}
}

void response_gen(proof_t proof, inst_t inst, data_ptr claim_secret, challenge_t challenge, data_ptr response) {
	block_ptr current = proof->first_block;
	while (current != NULL) {
		current->response_gen(current, proof, inst, claim_secret, challenge, response);
		claim_secret = (data_ptr)((char*)claim_secret + current->claim_secret_type->size);
		response = (data_ptr)((char*)response + current->response_type->size);
		current = current->next;
	}
}

int response_verify(proof_t proof, inst_t inst, data_ptr claim_public, challenge_t challenge, data_ptr response) {
	block_ptr current = proof->first_block;
	while (current != NULL) {
		if (!current->response_verify(current, proof, inst, claim_public, challenge, response)) return 0;
		claim_public = (data_ptr)((char*)claim_public + current->claim_public_type->size);
		response = (data_ptr)((char*)response + current->response_type->size);
		current = current->next;
	}
	return 1;
}

void _multi_init(type_ptr type, data_ptr data) {
	struct multi_type_s *self = (struct multi_type_s*)type;
	block_ptr current = self->proof->first_block;
	while (current != NULL) {
		type_ptr block_type = self->for_block(current);
		init(block_type, data);
		data = (data_ptr)((char*)data + block_type->size);
		current = current->next;
	}
}

void _multi_clear(type_ptr type, data_ptr data) {
	struct multi_type_s *self = (struct multi_type_s*)type;
	block_ptr current = self->proof->first_block;
	while (current != NULL) {
		type_ptr block_type = self->for_block(current);
		clear(block_type, data);
		data = (data_ptr)((char*)data + block_type->size);
		current = current->next;
	}
}

void _multi_write(type_ptr type, data_ptr data, FILE* stream) {
	struct multi_type_s *self = (struct multi_type_s*)type;
	block_ptr current = self->proof->first_block;
	while (current != NULL) {
		type_ptr block_type = self->for_block(current);
		write(block_type, data, stream);
		data = (data_ptr)((char*)data + block_type->size);
		current = current->next;
	}
}

void _multi_read(type_ptr type, data_ptr data, FILE* stream) {
	struct multi_type_s *self = (struct multi_type_s*)type;
	block_ptr current = self->proof->first_block;
	while (current != NULL) {
		type_ptr block_type = self->for_block(current);
		read(block_type, data, stream);
		data = (data_ptr)((char*)data + block_type->size);
		current = current->next;
	}
}

type_ptr _supplement_type_for_block(block_ptr block) {
	return block->supplement_type;
}

type_ptr _claim_secret_type_for_block(block_ptr block) {
	return block->claim_secret_type;
}

type_ptr _claim_public_type_for_block(block_ptr block) {
	return block->claim_public_type;
}

type_ptr _response_type_for_block(block_ptr block) {
	return block->response_type;
}

/***************************************************
* equals_public
*
* Verifies that a secret variable is equivalent to
* a public variable.
****************************************************/

typedef struct block_equals_public_s *block_equals_public_ptr;
typedef struct block_equals_public_s {
	block_t base;
	long secret_index;
	long public_index;
} block_equals_public_t[1];

// e	= challenge
// s	= inst->secret_values[secret_index]
// o_s	= inst->secret_openings[secret_index]
// C_s	= inst->secret_commitments[secret_index]
// p	= inst->public_values[public_index]

// [r]                        	= h ^ r	= R
// [e * o_s + r] * g ^ (e * p)	= (C_s) ^ e * R

void _equals_public_clear(block_ptr);
void _equals_public_claim_gen(block_ptr, proof_t, inst_t, data_ptr, data_ptr);
void _equals_public_response_gen(block_ptr, proof_t, inst_t, data_ptr, challenge_t, data_ptr);
int _equals_public_response_verify(block_ptr, proof_t, inst_t, data_ptr, challenge_t, data_ptr);
void block_equals_public(proof_t proof, long secret_index, long public_index) {
	block_equals_public_ptr self = (block_equals_public_ptr)pbc_malloc(sizeof(block_equals_public_t));
	self->base->clear = &_equals_public_clear;
	self->base->claim_gen = &_equals_public_claim_gen;
	self->base->response_gen = &_equals_public_response_gen;
	self->base->response_verify = &_equals_public_response_verify;
	self->base->supplement_type = (type_ptr)void_type;
	self->base->claim_secret_type = (type_ptr)proof->Z_type;
	self->base->claim_public_type = (type_ptr)proof->G_type;
	self->base->response_type = (type_ptr)proof->Z_type;
	self->secret_index = secret_index;
	self->public_index = public_index;
	block_insert(proof, (block_ptr)self);
}

void _equals_public_clear(block_ptr block) {
	pbc_free((block_equals_public_ptr)block);
}

void _equals_public_claim_gen(block_ptr block, proof_t proof, inst_t inst, data_ptr claim_secret, data_ptr claim_public) {
	element_ptr r = get_element((element_type_ptr)proof->Z_type, claim_secret);
	element_ptr R = get_element((element_type_ptr)proof->G_type, claim_public);
	
	// R = h ^ o_r
	element_random(r);
	element_pow_zn(R, proof->h, r);
}

void _equals_public_response_gen(block_ptr block, proof_t proof, inst_t inst, data_ptr claim_secret, challenge_t challenge, data_ptr response) {
	block_equals_public_ptr self = (block_equals_public_ptr)block;
	element_ptr r = get_element((element_type_ptr)proof->Z_type, claim_secret);
	element_ptr x = get_element((element_type_ptr)proof->Z_type, response);
	
	// x = e * o_s + r
	element_mul(x, challenge, inst->secret_openings[self->secret_index]);
	element_add(x, x, r);
}

int _equals_public_response_verify(block_ptr block, proof_t proof, inst_t inst, data_ptr claim_public, challenge_t challenge, data_ptr response) {
	block_equals_public_ptr self = (block_equals_public_ptr)block;
	element_ptr R = get_element((element_type_ptr)proof->G_type, claim_public);
	element_ptr x = get_element((element_type_ptr)proof->Z_type, response);
	
	// Verify [x] * g ^ (e * p) = (C_s) ^ e * R
	element_t gexp; element_init(gexp, proof->Z_type->field);
	element_mul(gexp, challenge, inst->public_values[self->public_index]);
	element_t left; element_init(left, proof->G_type->field);
	element_pow2_zn(left, proof->g, gexp, proof->h, x);
	element_t right; element_init(right, proof->G_type->field);
	element_pow_zn(right, inst->secret_commitments[self->secret_index], challenge);
	element_mul(right, right, R);
	int result = !element_cmp(left, right);
	element_clear(gexp);
	element_clear(left);
	element_clear(right);
	return result;
}

/***************************************************
* equals
*
* Verifies that a set of secret variables are
* equivalent.
****************************************************/

typedef struct block_equals_s *block_equals_ptr;
typedef struct block_equals_s {
	block_t base;
	array_type_t Zx_type;
	array_type_t Gx_type;
	int count;
	long *indices;
} block_equals_t[1];

// e    	= challenge
// s_#  	= inst->secret_values[indices[#]]
// o_s_#	= inst->secret_openings[indices[#]]
// C_s_#	= inst->secret_commitments[indices[#]]

// [(r, o_r_1, o_r_2, ...)]       	= (g ^ r * h ^ o_r_1, g ^ r * h ^ o_r_2, ...)	= R
// [(s_1, o_s_1, o_s_2, ...)]     	= (C_s_1, C_s_2, ...)
// [e(s_1, o_s_1, o_s_2, ...) + r]	= (C_s_1 ^ e * R, C_s_2 ^ e * R, ...)

void _equals_clear(block_ptr);
void _equals_claim_gen(block_ptr, proof_t, inst_t, data_ptr, data_ptr);
void _equals_response_gen(block_ptr, proof_t, inst_t, data_ptr, challenge_t, data_ptr);
int _equals_response_verify(block_ptr, proof_t, inst_t, data_ptr, challenge_t, data_ptr);
block_equals_ptr block_equals_base(proof_t proof, int count) {
	block_equals_ptr self = (block_equals_ptr)pbc_malloc(sizeof(block_equals_t));
	array_type_init(self->Zx_type, (type_ptr)proof->Z_type, 1 + count);
	array_type_init(self->Gx_type, (type_ptr)proof->G_type, count);
	self->base->clear = &_equals_clear;
	self->base->claim_gen = &_equals_claim_gen;
	self->base->response_gen = &_equals_response_gen;
	self->base->response_verify = &_equals_response_verify;
	self->base->supplement_type = (type_ptr)void_type;
	self->base->claim_secret_type = (type_ptr)self->Zx_type;
	self->base->claim_public_type = (type_ptr)self->Gx_type;
	self->base->response_type = (type_ptr)self->Zx_type;
	self->indices = (long*)pbc_malloc(sizeof(long) * count);
	self->count = count;
	block_insert(proof, (block_ptr)self);
	return self;
}


void equals_clear(struct block_s* block) {
	struct block_equals_s *self = (struct block_equals_s*)block;
	pbc_free(self);
}

void _equals_clear(block_ptr block) {
	block_equals_ptr self = (block_equals_ptr)block;
	pbc_free(self->indices);
	pbc_free(self);
}

void _equals_claim_gen(block_ptr block, proof_t proof, inst_t inst, data_ptr claim_secret, data_ptr claim_public) {
	block_equals_ptr self = (block_equals_ptr)block;
	int i; int count = self->count;
	element_ptr r = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, claim_secret, 0));
	element_random(r);
	for (i = 0; i < count; i++) {
		element_ptr o_r = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, claim_secret, 1 + i));
		element_ptr R = get_element((element_type_ptr)proof->G_type, get_item((array_type_ptr)self->Gx_type, claim_public, i));
		
		// R_# = g ^ r * h ^ o_r_#
		element_random(o_r);
		element_pow2_zn(R, proof->g, r, proof->h, o_r);
	}
}

void _equals_response_gen(block_ptr block, proof_t proof, inst_t inst, data_ptr claim_secret, challenge_t challenge, data_ptr response) {
	block_equals_ptr self = (block_equals_ptr)block;
	int i; int count = self->count;
	element_ptr r = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, claim_secret, 0));
	element_ptr x = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, response, 0));
	
	// x = e * s_1 + r
	element_mul(x, challenge, inst->secret_values[self->indices[0]]);
	element_add(x, x, r);
	
	for (i = 0; i < count; i++) {
		element_ptr o_r = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, claim_secret, 1 + i));
		element_ptr o_x = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, response, 1 + i));
		
		// o_x_# = e(o_s_#) + o_r_#
		element_mul(o_x, challenge, inst->secret_openings[self->indices[i]]);
		element_add(o_x, o_x, o_r);
	}
}

int _equals_response_verify(block_ptr block, proof_t proof, inst_t inst, data_ptr claim_public, challenge_t challenge, data_ptr response) {
	block_equals_ptr self = (block_equals_ptr)block;
	int i; int count = self->count;
	element_ptr x = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, response, 0));
	
	// Verify [x] = (C_s_1 ^ e * R, C_s_2 ^ e * R, ...)
	int result = 1;
	element_t left; element_init(left, proof->G_type->field);
	element_t right; element_init(right, proof->G_type->field);
	for (i = 0; i < count; i++) {
		element_ptr R = get_element((element_type_ptr)proof->G_type, get_item((array_type_ptr)self->Gx_type, claim_public, i));
		element_ptr o_x = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, response, i + 1));
		
		// Verify g ^ x * h ^ o_x_# = C_s_# ^ e * R_#
		element_pow2_zn(left, proof->g, x, proof->h, o_x);
		element_pow_zn(right, inst->secret_commitments[self->indices[i]], challenge);
		element_mul(right, right, R);
		if (element_cmp(left, right)) {
			result = 0;
			break;
		}
	}

	element_clear(left);
	element_clear(right);
	return result;
}

void require_equal(proof_t proof, int count, /* var_t a, var_t b, */ ...) {
	int i;
	struct block_equals_s *self = block_equals_base(proof, count);
	va_list argp;
	va_start(argp, count);
	for (i = 0; i < count; i++) self->indices[i] = var_secret_index(proof, va_arg(argp, var_t));
	va_end(argp);
}

void require_equal_many(proof_t proof, int count, var_t* vars) {
	int i;
	struct block_equals_s *self = block_equals_base(proof, count);
	for (i = 0; i < count; i++) self->indices[i] = var_secret_index(proof, vars[i]);
}

/***************************************************
* wsum_zero
*
* Verifies that the sum of a set of terms (product
* of a secret variable and a constant) is zero.
****************************************************/

typedef struct block_wsum_zero_s *block_wsum_zero_ptr;
typedef struct block_wsum_zero_s {
	block_t base;
	int count;
	long *indices;
	long *coefficients;
} block_wsum_zero_t[1];

// e    	= challenge
// k_#  	= coefficients[#]
// o_s_#	= inst->secret_openings[indices[#]]
// C_s_#	= inst->secret_commitments[indices[#]]

// [r]	= h ^ r	= R

// [r - e(o_s_1 * k_1 + o_s_2 * k_2 + ...)] * (C_s_1) ^ ek_1 * (C_s_2) ^ ek_2 * ...	= R

void _wsum_zero_clear(block_ptr);
void _wsum_zero_claim_gen(block_ptr, proof_t, inst_t, data_ptr, data_ptr);
void _wsum_zero_response_gen(block_ptr, proof_t, inst_t, data_ptr, challenge_t, data_ptr);
int _wsum_zero_response_verify(block_ptr, proof_t, inst_t, data_ptr, challenge_t, data_ptr);
block_wsum_zero_ptr block_wsum_zero_base(proof_t proof, int count) {
	block_wsum_zero_ptr self = (block_wsum_zero_ptr)pbc_malloc(sizeof(block_wsum_zero_t));
	self->base->clear = &_wsum_zero_clear;
	self->base->claim_gen = &_wsum_zero_claim_gen;
	self->base->response_gen = &_wsum_zero_response_gen;
	self->base->response_verify = &_wsum_zero_response_verify;
	self->base->supplement_type = (type_ptr)void_type;
	self->base->claim_secret_type = (type_ptr)proof->Z_type;
	self->base->claim_public_type = (type_ptr)proof->G_type;
	self->base->response_type = (type_ptr)proof->Z_type;
	self->indices = (long*)pbc_malloc(sizeof(long) * count);
	self->coefficients = (long*)pbc_malloc(sizeof(long) * count);
	self->count = count;
	block_insert(proof, (block_ptr)self);
	return self;
}

void _wsum_zero_clear(block_ptr block) {
	block_wsum_zero_ptr self = (block_wsum_zero_ptr)block;
	pbc_free(self->indices);
	pbc_free(self->coefficients);
	pbc_free(self);
}

void _wsum_zero_claim_gen(block_ptr block, proof_t proof, inst_t inst, data_ptr claim_secret, data_ptr claim_public) {
	element_ptr r = get_element((element_type_ptr)proof->Z_type, claim_secret);
	element_ptr R = get_element((element_type_ptr)proof->G_type, claim_public);
	
	// R = h ^ o_r
	element_random(r);
	element_pow_zn(R, proof->h, r);
}

void _wsum_zero_response_gen(block_ptr block, proof_t proof, inst_t inst, data_ptr claim_secret, challenge_t challenge, data_ptr response) {
	block_wsum_zero_ptr self = (block_wsum_zero_ptr)block;
	int i; int count = self->count;
	element_ptr r = get_element((element_type_ptr)proof->Z_type, claim_secret);
	element_ptr x = get_element((element_type_ptr)proof->Z_type, response);
	
	// x = r - e(o_s_1 * k_1 + o_s_2 * k_2 + ...)
	element_t term; element_init(term, proof->Z_type->field);
	element_set0(x);
	for (i = 0; i < count; i++) {
		element_mul_si(term, inst->secret_openings[self->indices[i]], self->coefficients[i]);
		element_add(x, x, term);
	}
	element_mul(x, x, challenge);
	element_sub(x, r, x);
	element_clear(term);
}

int _wsum_zero_response_verify(block_ptr block, proof_t proof, inst_t inst, data_ptr claim_public, challenge_t challenge, data_ptr response) {
	block_wsum_zero_ptr self = (block_wsum_zero_ptr)block;
	int i; int count = self->count;
	element_ptr R = get_element((element_type_ptr)proof->G_type, claim_public);
	element_ptr x = get_element((element_type_ptr)proof->Z_type, response);
	
	// Verify [x] * (C_s_1) ^ (e * k_1) * (C_s_2) ^ (e * k_2) * ... = R
	element_t left; element_init(left, proof->G_type->field);
	element_t term; element_init(term, proof->G_type->field);
	for (i = 0; i < count; i++) {
		element_mul_si(term, inst->secret_commitments[self->indices[i]], self->coefficients[i]);
		element_mul(left, left, term);
	}
	element_pow2_zn(left, proof->h, x, left, challenge);
	int result = !element_cmp(left, R);
	element_clear(left);
	element_clear(term);
	return result;
}

void require_sum(proof_t proof, var_t sum, var_t addend_1, var_t addend_2) {
	block_wsum_zero_ptr self = block_wsum_zero_base(proof, 3);
	self->coefficients[0] = -1; self->indices[0] = var_secret_index(proof, sum);
	self->coefficients[1] = 1; self->indices[1] = var_secret_index(proof, addend_1);
	self->coefficients[2] = 1; self->indices[2] = var_secret_index(proof, addend_2);
}

void require_dif(proof_t proof, var_t dif, var_t minuend, var_t subtrahend) {
	block_wsum_zero_ptr self = block_wsum_zero_base(proof, 3);
	self->coefficients[0] = -1; self->indices[0] = var_secret_index(proof, dif);
	self->coefficients[1] = 1; self->indices[1] = var_secret_index(proof, minuend);
	self->coefficients[2] = -1; self->indices[2] = var_secret_index(proof, subtrahend);
}

void require_wsum_zero(proof_t proof, int count, /* long a_coeff, var_t a, long b_coeff, var_t b, */ ...) {
	int i;
	block_wsum_zero_ptr self = block_wsum_zero_base(proof, count);
	va_list argp;
	va_start(argp, count);
	for (i = 0; i < count; i++) {
		self->coefficients[i] = va_arg(argp, long);
		self->indices[i] = var_secret_index(proof, va_arg(argp, var_t));
	}
	va_end(argp);
}

void require_wsum_zero_many(proof_t proof, int count, long* coeffs, var_t* vars) {
	int i;
	block_wsum_zero_ptr self = block_wsum_zero_base(proof, count);
	for (i = 0; i < count; i++) {
		self->coefficients[i] = coeffs[i];
		self->indices[i] = var_secret_index(proof, vars[i]);
	}
}

/***************************************************
* product
*
* Verifies that the product of two secret variables
* is equivalent to a third.
****************************************************/

typedef struct block_product_s *block_product_ptr;
typedef struct block_product_s {
	block_t base;
	array_type_t Zx_type;
	array_type_t Gx_type;
	long product_index;
	long factor_1_index;
	long factor_2_index;
} block_product_t[1];

// o_p  	= inst->secret_openings[product_index]
// C_p  	= inst->secret_commitments[product_index]
// f_1  	= inst->secret_values[factor_1_index]
// o_f_1  	= inst->secret_openings[factor_1_index]
// C_f_1	= inst->secret_commitments[factor_1_index]
// o_f_1  	= inst->secret_openings[factor_2_index]
// C_f_2	= inst->secret_commitments[factor_2_index]

// [(r_1, r_2, r_3)]                	= (g ^ r_1 * h ^ r_2, C_f_2 ^ r_1 * h ^ r_3)	= R
// [(f_1, o_f_1, o_p - o_f_2 * f_1)]	= (C_f_1, C_p)

void _product_clear(block_ptr);
void _product_claim_gen(block_ptr, proof_t, inst_t, data_ptr, data_ptr);
void _product_response_gen(block_ptr, proof_t, inst_t, data_ptr, challenge_t, data_ptr);
int _product_response_verify(block_ptr, proof_t, inst_t, data_ptr, challenge_t, data_ptr);
void block_product(proof_t proof, long product_index, long factor_1_index, long factor_2_index) {
	block_product_ptr self = (block_product_ptr)pbc_malloc(sizeof(block_product_t));
	array_type_init(self->Zx_type, (type_ptr)proof->Z_type, 3);
	array_type_init(self->Gx_type, (type_ptr)proof->G_type, 2);
	self->base->clear = &_product_clear;
	self->base->claim_gen = &_product_claim_gen;
	self->base->response_gen = &_product_response_gen;
	self->base->response_verify = &_product_response_verify;
	self->base->supplement_type = (type_ptr)void_type;
	self->base->claim_secret_type = (type_ptr)self->Zx_type;
	self->base->claim_public_type = (type_ptr)self->Gx_type;
	self->base->response_type = (type_ptr)self->Zx_type;
	self->product_index = product_index;
	self->factor_1_index = factor_1_index;
	self->factor_2_index = factor_2_index;
	block_insert(proof, (block_ptr)self);
}

void _product_clear(block_ptr block) {
	pbc_free((block_product_ptr)block);
}

void _product_claim_gen(block_ptr block, proof_t proof, inst_t inst, data_ptr claim_secret, data_ptr claim_public) {
	block_product_ptr self = (block_product_ptr)block;
	element_ptr r_1 = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, claim_secret, 0));
	element_ptr r_2 = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, claim_secret, 1));
	element_ptr r_3 = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, claim_secret, 2));
	element_ptr R_1 = get_element((element_type_ptr)proof->G_type, get_item((array_type_ptr)self->Gx_type, claim_public, 0));
	element_ptr R_2 = get_element((element_type_ptr)proof->G_type, get_item((array_type_ptr)self->Gx_type, claim_public, 1));
	
	// R_1 = g ^ r_1 * h ^ r_2
	element_random(r_1);
	element_random(r_2);
	element_pow2_zn(R_1, proof->g, r_1, proof->h, r_2);
	
	// R_2 = C_f_2 ^ r_1 * h ^ r_3
	element_random(r_3);
	element_pow2_zn(R_2, inst->secret_commitments[self->factor_2_index], r_1, proof->h, r_3);
}

void _product_response_gen(block_ptr block, proof_t proof, inst_t inst, data_ptr claim_secret, challenge_t challenge, data_ptr response) {
	block_product_ptr self = (block_product_ptr)block;
	element_ptr r_1 = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, claim_secret, 0));
	element_ptr r_2 = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, claim_secret, 1));
	element_ptr r_3 = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, claim_secret, 2));
	element_ptr x_1 = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, response, 0));
	element_ptr x_2 = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, response, 1));
	element_ptr x_3 = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, response, 2));

	// x_1 = e * f_1 + r_1
	element_mul(x_1, inst->secret_values[self->factor_1_index], challenge);
	element_add(x_1, x_1, r_1);
	
	// x_2 = e * o_f_1 + r_2
	element_mul(x_2, inst->secret_openings[self->factor_1_index], challenge);
	element_add(x_2, x_2, r_2);
	
	// x_3 = e(o_p - o_f_2 * f_1) + r_3
	element_mul(x_3, inst->secret_openings[self->factor_2_index], inst->secret_values[self->factor_1_index]);
	element_sub(x_3, inst->secret_openings[self->product_index], x_3);
	element_mul(x_3, x_3, challenge);
	element_add(x_3, x_3, r_3);
}

int _product_response_verify(block_ptr block, proof_t proof, inst_t inst, data_ptr claim_public, challenge_t challenge, data_ptr response) {
	block_product_ptr self = (block_product_ptr)block;
	element_ptr R_1 = get_element((element_type_ptr)proof->G_type, get_item((array_type_ptr)self->Gx_type, claim_public, 0));
	element_ptr R_2 = get_element((element_type_ptr)proof->G_type, get_item((array_type_ptr)self->Gx_type, claim_public, 1));
	element_ptr x_1 = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, response, 0));
	element_ptr x_2 = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, response, 1));
	element_ptr x_3 = get_element((element_type_ptr)proof->Z_type, get_item((array_type_ptr)self->Zx_type, response, 2));
	
	// Verify g ^ x_1 * h ^ x_2 = C_f_1 ^ e * R_1
	int result = 1;
	element_t left; element_init(left, proof->G_type->field);
	element_t right; element_init(right, proof->G_type->field);
	element_pow2_zn(left, proof->g, x_1, proof->h, x_2);
	element_pow_zn(right, inst->secret_commitments[self->factor_1_index], challenge);
	element_mul(right, right, R_1);
	if (element_cmp(left, right)) {
		result = 0;
		goto end;
	}
	
	// Verify C_f_2 ^ x_1 * h ^ x_3 = C_p ^ e * R_2
	element_pow2_zn(left, inst->secret_commitments[self->factor_2_index], x_1, proof->h, x_3);
	element_pow_zn(right, inst->secret_commitments[self->product_index], challenge);
	element_mul(right, right, R_2);
	result = !element_cmp(left, right);

end:
	element_clear(left);
	element_clear(right);
	return result;
}

void require_mul(proof_t proof, var_t product, var_t factor_1, var_t factor_2) {
	block_product(proof,
		var_secret_index(proof, product),
		var_secret_index(proof, factor_1),
		var_secret_index(proof, factor_2));
}
