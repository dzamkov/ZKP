#include <assert.h>
#include "zkp.h"
#include "zkp_internal.h"

void computation_insert(proof_t proof, struct computation_s *computation) {
	if (proof->last_computation == NULL) {
		proof->first_computation = computation;
	} else {
		proof->last_computation->next = computation;
	}
	proof->last_computation = computation;
	computation->next = NULL;
}

void computations_clear(proof_t proof) {
	struct computation_s* current = proof->first_computation;
	while (current != NULL) {
		current->clear(current);
		current = current->next;
	}
}

void inst_update(proof_t proof, inst_t inst) {
	struct computation_s* current = proof->first_computation;
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

struct computation_set_s {
	struct computation_s base;
	var_t var;
	element_t value;
};

void set_clear(struct computation_s *c) {
	struct computation_set_s *self = (struct computation_set_s*)c;
	element_clear(self->value);
	pbc_free(self);
};

void set_apply(struct computation_s *c, proof_t proof, inst_t inst) {
	struct computation_set_s *self = (struct computation_set_s*)c;
	inst_var_set(proof, inst, self->var, self->value);
};

struct computation_set_s* computation_set_base(proof_t proof, var_t var) {
	struct computation_set_s *self = (struct computation_set_s*)pbc_malloc(sizeof(struct computation_set_s));
	self->base.clear = &set_clear;
	self->base.apply = &set_apply;
	self->base.is_secret = var_is_secret(var);
	self->var = var;
	element_init(self->value, proof->Z);
	computation_insert(proof, &self->base);
	return self;
}

void computation_set(proof_t proof, var_t var, element_t value) {
	struct computation_set_s *self = computation_set_base(proof, var);
	element_set(self->value, value);
}

var_t var_const(proof_t proof, element_t value) {
	var_t var = var_public(proof);
	computation_set(proof, var, value);
	return var;
}

void computation_set_mpz(proof_t proof, var_t var, mpz_t value) {
	struct computation_set_s *self = computation_set_base(proof, var);
	element_set_mpz(self->value, value);
}

var_t var_const_mpz(proof_t proof, mpz_t value) {
	var_t var = var_public(proof);
	computation_set_mpz(proof, var, value);
	return var;
}

void computation_set_si(proof_t proof, var_t var, long int value) {
	struct computation_set_s *self = computation_set_base(proof, var);
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

struct computation_mov_s {
	struct computation_s base;
	var_t dest;
	var_t src;
};

void mov_clear(struct computation_s *c) {
	struct computation_mov_s *self = (struct computation_mov_s*)c;
	pbc_free(self);
};

void mov_apply(struct computation_s *c, proof_t proof, inst_t inst) {
	struct computation_mov_s *self = (struct computation_mov_s*)c;
	inst_var_set(proof, inst, self->dest, inst_var_get(proof, inst, self->src));
};

void computation_mov(proof_t proof, var_t dest, var_t src) {
	struct computation_mov_s *self = (struct computation_mov_s*)pbc_malloc(sizeof(struct computation_mov_s));
	self->base.clear = &mov_clear;
	self->base.apply = &mov_apply;
	self->base.is_secret = var_is_secret(dest) || var_is_secret(src);
	self->dest = dest;
	self->src = src;
	computation_insert(proof, &self->base);
}
