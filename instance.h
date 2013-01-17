#ifndef INSTANCE_H_
#define INSTANCE_H_

#include <pbc.h>

// A reference to a proof variable, which may either be a
// constant (intrinsic to the proof, same for all instances), public (set
// consistently between the prover and verifier for each instance), or secret 
// (set by the prover on each instance and kept unknown to the verifier).
typedef unsigned int var_t;

// Contains information about a specific instance of a proof, including
// the values of all variables.
struct instance_s {
	
	// The number of secret variables maintained by this instance.
	int num_secret;
	
	// The number of public variables maintained by this instance.
	int num_public;
	
	// The values of the variables in this instance of the proof.
	mpz_t *values;
	
	// The openings for secret variables. These can be set randomly for each instance
	// of the proof. This will be NULL for the verifier.
	mpz_t *openings;
	
	// Random values used to compute pederson commitments.
	element_t g;
	element_t h;
	
	// The commitments for secret variables, generated using C_x = g^x * h^(o_x) where
	// x is the variable value and o_x is the opening for the variable. The verifier must
	// obtain these commitments from the prover.
	element_t *commitments;
};
typedef struct instance_s *instance_ptr;
typedef struct instance_s instance_t[1];

// Sets the value of a variable in an instance.
static inline void instance_set(instance_t instance, var_t var, mpz_t value) {
	mpz_set(instance->values[var], value);
}

// Gets the value of a variable in an instance.
static inline mpz_ptr instance_get(instance_t instance, var_t var) {
	return instance->values[var];
}

// Sets the opening of a variable in an instance.
static inline void instance_set_opening(instance_t instance, var_t var, mpz_t opening) {
	mpz_set(instance->openings[var], opening);
}

// Gets the opening of a variable in an instance.
static inline mpz_ptr instance_get_opening(instance_t instance, var_t var) {
	return instance->openings[var];
}

// Sets the commitment of a variable in an instance.
static inline void instance_set_commitment(instance_t instance, var_t var, element_t commitment) {
	element_set(instance->commitments[var], commitment);
}

// Gets the commitment of a variable in an instance.
static inline element_ptr instance_get_commitment(instance_t instance, var_t var) {
	return instance->commitments[var];
}

// Initializes an instance for the prover.
void instance_init_prover(instance_t instance, int num_secret, int num_public, element_t g, element_t h);

// Clears a prover instance.
void instance_clear_prover(instance_t instance);

// Initializes an instance for the verifier.
void instance_init_verifier(instance_t instance, int num_secret, int num_public, element_t g, element_t h);

// Clears a verifier instance.
void instance_clear_verifier(instance_t instance);

// Sets the value of a secret variable in an instance, randomly creating an opening and a corresponding
// commitment.
void instance_set_secret(instance_t instance, var_t var, mpz_t value);

#endif // INSTANCE_H_
