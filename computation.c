#include <assert.h>
#include "zkp.h"
#include "zkp_internal.h"

void computation_insert(proof_t proof, int is_secret, struct computation_s *computation) {
	if (is_secret) {
		if (proof->last_secret_computation == NULL) {
			proof->first_secret_computation = computation;
		} else {
			proof->last_secret_computation->next = computation;
		}
		proof->last_secret_computation = computation;
		computation->next = proof->first_public_computation;
	} else {
		if (proof->last_public_computation == NULL) {
			if (proof->last_secret_computation != NULL) {
				proof->last_secret_computation->next = computation;
			}
			proof->first_public_computation = computation;
		} else {
			proof->last_public_computation->next = computation;
		}
		proof->last_public_computation = computation;
		computation->next = NULL;
	}
}

void computations_clear(proof_t proof) {
	struct computation_s* current = proof->first_public_computation;
	while (current != NULL) {
		current->clear(current);
		current = current->next;
	}
}

void inst_update(proof_t proof, inst_t inst) {
	struct computation_s* current = proof->first_public_computation;
	struct computation_s* end = (inst->secret_values != NULL) ? NULL : proof->first_secret_computation;
	while(current != end) {
		current->apply(current, proof, inst);
		current = current->next;
	}
}

/***************************************************
* Set
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
	self->var = var;
	element_init(self->value, proof->Z);
	computation_insert(proof, var_is_secret(var), &self->base);
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
