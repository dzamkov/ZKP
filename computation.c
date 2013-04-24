#include <assert.h>
#include "zkp.h"
#include "zkp_internal.h"

void computation_insert(proof_t proof, computation_ptr computation) {
	if (proof->last_computation == NULL) {
		proof->first_computation = computation;
	} else {
		proof->last_computation->next = computation;
	}
	proof->last_computation = computation;
	computation->next = NULL;
}

void computations_clear(proof_t proof) {
	computation_ptr current = proof->first_computation;
	while (current != NULL) {
		current->clear(current);
		current = current->next;
	}
}

void inst_update(proof_t proof, inst_t inst) {
	computation_ptr current = proof->first_computation;
	while(current != NULL) {
		if (!current->is_secret || inst->secret_values != NULL)
			current->apply(current, proof, inst);
		current = current->next;
	}
}

/***************************************************
* set
*
* Sets a variable to a constant value.
****************************************************/

typedef struct computation_set_s *computation_set_ptr;
typedef struct computation_set_s {
	computation_t base;
	var_t var;
	element_t value;
} computation_set_t[1];

void _set_clear(computation_ptr computation);
void _set_apply(computation_ptr computation, proof_t proof, inst_t inst);
computation_set_ptr computation_set_base(proof_t proof, var_t var) {
	computation_set_ptr self = (computation_set_ptr)pbc_malloc(sizeof(computation_set_t));
	self->base->clear = &_set_clear;
	self->base->apply = &_set_apply;
	self->base->is_secret = var_is_secret(var);
	self->var = var;
	element_init(self->value, proof->Z_type->field);
	computation_insert(proof, self->base);
	return self;
}

void _set_clear(computation_ptr computation) {
	computation_set_ptr self = (computation_set_ptr)computation;
	element_clear(self->value);
	pbc_free(self);
}

void _set_apply(computation_ptr computation, proof_t proof, inst_t inst) {
	computation_set_ptr self = (computation_set_ptr)computation;
	inst_var_set(proof, inst, self->var, self->value);
}


void computation_set(proof_t proof, var_t var, element_t value) {
	computation_set_ptr self = computation_set_base(proof, var);
	element_set(self->value, value);
}

var_t var_const(proof_t proof, element_t value) {
	var_t var = var_public(proof);
	computation_set(proof, var, value);
	return var;
}

void computation_set_mpz(proof_t proof, var_t var, mpz_t value) {
	computation_set_ptr self = computation_set_base(proof, var);
	element_set_mpz(self->value, value);
}

var_t var_const_mpz(proof_t proof, mpz_t value) {
	var_t var = var_public(proof);
	computation_set_mpz(proof, var, value);
	return var;
}

void computation_set_si(proof_t proof, var_t var, long int value) {
	computation_set_ptr self = computation_set_base(proof, var);
	element_set_si(self->value, value);
}

var_t var_const_si(proof_t proof, long int value) {
	var_t var = var_public(proof);
	computation_set_si(proof, var, value);
	return var;
}

/***************************************************
* mov
*
* Sets a variable to a constant value.
****************************************************/

typedef struct computation_mov_s *computation_mov_ptr;
typedef struct computation_mov_s {
	struct computation_s base;
	var_t dest;
	var_t src;
} computation_mov_t[1];

void _mov_clear(computation_ptr computation);
void _mov_apply(computation_ptr computation, proof_t proof, inst_t inst);
void computation_mov(proof_t proof, var_t dest, var_t src) {
	computation_mov_ptr self = (computation_mov_ptr)pbc_malloc(sizeof(computation_mov_t));
	self->base.clear = &_mov_clear;
	self->base.apply = &_mov_apply;
	self->base.is_secret = var_is_secret(dest) || var_is_secret(src);
	self->dest = dest;
	self->src = src;
	computation_insert(proof, &self->base);
}

void _mov_clear(computation_ptr computation) {
	computation_mov_ptr self = (computation_mov_ptr)computation;
	pbc_free(self);
}

void _mov_apply(computation_ptr computation, proof_t proof, inst_t inst) {
	computation_mov_ptr self = (computation_mov_ptr)computation;
	inst_var_set(proof, inst, self->dest, inst_var_get(proof, inst, self->src));
}
