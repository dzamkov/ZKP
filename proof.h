#ifndef PROOF_H_
#define PROOF_H_

#include <pbc.h>

// Describes a zero-knowledge proof.
struct proof_s {
	
	// The number of secret variables in this proof.
	int num_secret;
	
	// The number of public variables in this proof.
	int num_public;
	
	// The number of constant variables in this proof.
	int num_const;
	
	// The number of extra witness elements in the Z field.
	int num_extra_Z;
	
	// The number of extra witness elements in the G field.
	int num_extra_G;
	
	// The g element for this proof, used for computing commitments.
	element_t g;
	
	// The h element for this proof, used for computing commitments.
	element_t h;
	
	
	// The number of constant variables allocated.
	int num_const_alloc;
	
	// The values of the constant variables.
	mpz_t* consts;
	
};
typedef struct proof_s *proof_ptr;
typedef struct proof_s proof_t[1];

// Initializes a proof, setting it to a default empty state.
void proof_init(proof_t proof, element_t g, element_t h);

// Frees the space occupied by a proof.
void proof_clear(proof_t proof);


// A reference to a proof variable, which may either be a
// constant (intrinsic to the proof, same for all instances), public (set
// consistently between the prover and verifier for each instance), or secret 
// (set by the prover on each instance and kept unknown to the verifier).
typedef unsigned long var_t;

// Declares a new secret variable in the given proof.
var_t new_secret(proof_t proof);

// Declares a new public variable in the given proof.
var_t new_public(proof_t proof);

// Defines a new constant variable in the given proof.
var_t new_const(proof_t proof, mpz_t value);

// Defines a new constant variable in the given proof.
var_t new_const_ui(proof_t proof, unsigned long int value);

// Retrieves a pointer to the value of a constant variable in the given proof.
mpz_ptr lookup_const(proof_t proof, var_t var);


// A specific instance of a proof, including the values of all known variables.
struct instance_s {
	
	// The values of the secret variables. This will be NULL for the verifier.
	mpz_t *secret_values;
	
	// The openings for the secret variables. This will be NULL for the verifier.
	mpz_t *secret_openings;
	
	// The commitments for the secret variables. The verifier must get these from the
	// prover.
	element_t *secret_commitments;
	
	// The values of the public variables.
	mpz_t *public_values;
};
typedef struct instance_s *instance_ptr;
typedef struct instance_s instance_t[1];

// Retrieves a pointer to the value of a variable in an instance of the given proof.
mpz_ptr lookup(proof_t proof, instance_t instance, var_t var);


// A witness of an instance of a proof. This information is generated before a challenge is given.
struct witness_s {

	// The randomizers for corresponding secret variables. This will be NULL for the verifier.
	mpz_t *randomizer_values;
	
	// The openings for the randomizers. This will be NULL for the verifier.
	mpz_t *randomizer_openings;
	
	// The commitments for the randomizers. 
	element_t *randomizer_commitments;
	
	// Extra witness information in the Z field.
	mpz_t *extra_Z;
	
	// Extra witness information in the G field.
	element_t *extra_G;
	
};
typedef struct witness_s *witness_ptr;
typedef struct witness_s witness_t[1];

// A response to challenge for a witness.
struct response_s {

	// Boxed values of the form [x] = ex + r_x where [x] is the boxed value, e is the challenge,
	// x is the corresponding secret value and r_x is the randomizer for that value.
	mpz_t *boxed_values;

	// Boxed openings of the form [o_x] = eo_x + r_{o_x} where [o_x] is the boxed opening, e is the challenge,
	// o_x is the corresponding secret opening and r_{o_x} is the randomizer for that opening.
	mpz_t *boxed_openings;
};
typedef struct response_s *response_ptr;
typedef struct response_s response_t[1];

#endif // PROOF_H_
