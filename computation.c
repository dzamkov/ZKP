#include <assert.h>
#include <pbc.h>
#include "proof.h"
#include "computation.h"

void insert_computation(proof_t proof, int is_secret, struct computation_s *c) {
	if (is_secret) {
		if (proof->last_secret_computation == NULL) {
			proof->first_secret_computation = c;
			proof->last_secret_computation = c;
		} else {
			proof->last_secret_computation->next = c;
			proof->last_secret_computation = c;
		}
		c->next = proof->first_public_computation;
	} else {
		if (proof->last_public_computation == NULL) {
			if (proof->last_secret_computation != NULL) {
				proof->last_secret_computation->next = c;
			}
			proof->first_public_computation = c;
			proof->last_public_computation = c;
		} else {
			proof->last_public_computation->next = c;
			proof->last_public_computation = c;
		}
		c->next = NULL;
	}
}

void clear_computations(struct computation_s *first) {
	struct computation_s* current = first;
	while (current != NULL) {
		current->clear(current);
		current = current->next;
	}
}

void apply_computations(struct computation_s *start, struct computation_s *end,  proof_t proof, inst_t inst) {
	struct computation_s* current = start;
	while(current != end) {
		current->apply(current, proof, inst);
		current = current->next;
	}
}


struct computation_assign_s {
	struct computation_s base;
	var_t var;
	mpz_t value;
};

void assign_clear(struct computation_s *c) {
	struct computation_assign_s *self = (struct computation_assign_s*)c;
	mpz_clear(self->value);
	pbc_free(self);
};

void assign_apply(struct computation_s *c, proof_t proof, inst_t inst) {
	struct computation_assign_s *self = (struct computation_assign_s*)c;
	inst_set(proof, inst, self->var, self->value);
};

void compute_assign(proof_t proof, var_t var, mpz_t value) {
	struct computation_assign_s *self = (struct computation_assign_s*)pbc_malloc(sizeof(struct computation_assign_s));
	self->base.clear = &assign_clear;
	self->base.apply = &assign_apply;
	self->var = var;
	mpz_init_set(self->value, value);
	insert_computation(proof, is_secret(var), &self->base);
}


struct computation_assign_ui_s {
	struct computation_s base;
	var_t var;
	unsigned long int value;
};

void assign_ui_clear(struct computation_s *c) {
	pbc_free(c);
};

void assign_ui_apply(struct computation_s *c, proof_t proof, inst_t inst) {
	struct computation_assign_ui_s *self = (struct computation_assign_ui_s*)c;
	inst_set_ui(proof, inst, self->var, self->value);
};

void compute_assign_ui(proof_t proof, var_t var, unsigned long int value) {
	struct computation_assign_ui_s *self = (struct computation_assign_ui_s*)pbc_malloc(sizeof(struct computation_assign_ui_s));
	self->base.clear = &assign_ui_clear;
	self->base.apply = &assign_ui_apply;
	self->var = var;
	self->value = value;
	insert_computation(proof, is_secret(var), &self->base);
}
