// Requires:
//  * pbc.h
//  * proof.h
#ifndef ZKP_COMPUTATION_H_
#define ZKP_COMPUTATION_H_

// A computational procedure for a proof that calculates the values of a subset of
// instance variables.
struct computation_s {
	void (*clear)(struct computation_s*);
	void (*apply)(struct computation_s* computation, proof_t, inst_t);
	struct computation_s *next;
};

// Inserts a computation into a proof that assigns a constant value to a variable.
void compute_assign(proof_t proof, var_t var, mpz_t value);
void compute_assign_ui(proof_t proof, var_t var, unsigned long int value);

#endif // ZKP_COMPUTATION_H_
