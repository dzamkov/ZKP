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


struct computation_set_s {
	struct computation_s base;
	var_t var;
	mpz_t value;
};

void set_clear(struct computation_s *c) {
	struct computation_set_s *self = (struct computation_set_s*)c;
	mpz_clear(self->value);
	pbc_free(self);
};

void set_apply(struct computation_s *c, proof_t proof, inst_t inst) {
	struct computation_set_s *self = (struct computation_set_s*)c;
	inst_var_set(proof, inst, self->var, self->value);
};

void computation_set(proof_t proof, var_t var, mpz_t value) {
	struct computation_set_s *self = (struct computation_set_s*)pbc_malloc(sizeof(struct computation_set_s));
	self->base.clear = &set_clear;
	self->base.apply = &set_apply;
	self->var = var;
	mpz_init_set(self->value, value);
	computation_insert(proof, is_secret(var), &self->base);
}

var_t new_const(proof_t proof, mpz_t value) {
	var_t var = new_public(proof);
	computation_set(proof, var, value);
	return var;
}


struct computation_set_i_s {
	struct computation_s base;
	var_t var;
	long int value;
	int is_signed;
};

void set_i_clear(struct computation_s *c) {
	pbc_free(c);
};

void set_i_apply(struct computation_s *c, proof_t proof, inst_t inst) {
	struct computation_set_i_s *self = (struct computation_set_i_s*)c;
	if (self->is_signed) {
		inst_var_set_si(proof, inst, self->var, (signed long int)self->value);
	} else {
		inst_var_set_ui(proof, inst, self->var, (unsigned long int)self->value);
	}
};

void computation_set_i(proof_t proof, var_t var, long int value, int is_signed) {
	struct computation_set_i_s *self = (struct computation_set_i_s*)pbc_malloc(sizeof(struct computation_set_i_s));
	self->base.clear = &set_i_clear;
	self->base.apply = &set_i_apply;
	self->var = var;
	self->value = value;
	self->is_signed = is_signed;
	computation_insert(proof, is_secret(var), &self->base);
}

void computation_set_ui(proof_t proof, var_t var, unsigned long int value) {
	computation_set_i(proof, var, value, 0);
}

var_t new_const_ui(proof_t proof, unsigned long int value) {
	var_t var = new_public(proof);
	computation_set_ui(proof, var, value);
	return var;
}

void computation_set_si(proof_t proof, var_t var, signed long int value) {
	computation_set_i(proof, var, value, 1);
}

var_t new_const_si(proof_t proof, signed long int value) {
	var_t var = new_public(proof);
	computation_set_si(proof, var, value);
	return var;
}
