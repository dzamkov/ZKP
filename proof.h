// Requires:
//  * pbc.h
#ifndef ZKP_PROOF_H_
#define ZKP_PROOF_H_

struct computation_s;

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
	
	
	// The first public computation for this proof.
	struct computation_s *first_public_computation;
	
	// The last public computation for this proof. 
	struct computation_s *last_public_computation;
	
	// The first secret computation for this proof. (Note that secret computations
	// always occur after public computations because the result of a public computation
	// can never depend on the result of a secret computation)
	struct computation_s *first_secret_computation;
	
	// The last secret computatino for this proof.
	struct computation_s *last_secret_computation;
	
};
typedef struct proof_s *proof_ptr;
typedef struct proof_s proof_t[1];

// Initializes a proof, setting it to a default empty state.
void proof_init(proof_t proof, element_t g, element_t h);

// Frees the space occupied by a proof.
void proof_clear(proof_t proof);


// A reference to a proof variable, which may either be secret (set by the 
// prover on each instance and kept unknown to the verifier) or public (set
// consistently between the prover and verifier for each instance)
typedef unsigned long var_t;

// Declares a new secret variable in the given proof.
var_t new_secret(proof_t proof);

// Declares a new public variable in the given proof.
var_t new_public(proof_t proof);

// Defines a new constant variable in the given proof.
var_t new_const(proof_t proof, mpz_t value);
var_t new_const_ui(proof_t proof, unsigned long int value);

// Indicates whether the given variable is secret.
int is_secret(var_t var);

// Indicates whether the given variable is public.
int is_public(var_t var);

// A specific instance of a proof, including the values of all known variables.
struct inst_s {
	
	// The values of the secret variables. This will be NULL for the verifier.
	mpz_t *secret_values;
	
	// The openings for the secret variables. This will be NULL for the verifier.
	mpz_t *secret_openings;
	
	// The commitments for the secret variables. The verifier must get these from the
	// prover.
	element_t *secret_commitments;
	
	// Extra proof-dependent secret information.
	char *secret_extra;
	
	// The values of the public variables.
	mpz_t *public_values;
};
typedef struct inst_s *inst_ptr;
typedef struct inst_s inst_t[1];

// Initializes a prover instance of a proof.
void inst_init_prover(proof_t proof, inst_t inst);

// Initializes a verifier instance of a proof.
void inst_init_verifier(proof_t proof, inst_t inst);

// Frees the space occupied by an instance of a proof.
void inst_clear(proof_t proof, inst_t inst);

// Sets the value of a variable in an instance of a proof. If the variable is
// secret, a random opening and corresponding commitment will automatically be
// generated.
void inst_set(proof_t proof, inst_t inst, var_t var, mpz_t value);
void inst_set_ui(proof_t proof, inst_t inst, var_t var, unsigned long int value);

// Retrieves the value of a variable in an instance of the given proof.
mpz_ptr inst_get(proof_t proof, inst_t inst, var_t var);

// Applies all proof computations on the given instance.
void inst_update(proof_t proof, inst_t inst);


// A witness of an instance of a proof. This information is generated before a challenge is given.
struct witness_s {

	// The randomizers for corresponding secret variables. This will be NULL for the verifier.
	mpz_t *randomizer_values;
	
	// The openings for the randomizers. This will be NULL for the verifier.
	mpz_t *randomizer_openings;
	
	// The commitments for the randomizers. 
	element_t *randomizer_commitments;
	
	// Extra proof-dependent witness information.
	char *extra;
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

#endif // ZKP_PROOF_H_
