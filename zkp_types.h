#ifndef ZKP_TYPES_H_
#define ZKP_TYPES_H_

struct computation_s;
struct block_s;

// Describes a zero-knowledge proof.
struct proof_s {
	
	// The number of secret variables in this proof.
	int num_secret;
	
	// The number of public variables in this proof.
	int num_public;
	
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
	
	
	// The first block for this proof.
	struct block_s *first_block;
	
	// The last block for this proof.
	struct block_s *last_block;
	
	// The total size of a witness for this proof.
	size_t witness_size;
};
typedef struct proof_s *proof_ptr;
typedef struct proof_s proof_t[1];

// A reference to a proof variable, which may either be secret (set by the 
// prover on each instance and kept unknown to the verifier) or public (set
// consistently between the prover and verifier for each instance).
typedef unsigned long var_t;

// A specific instance of a proof, containing the values of all known variables.
struct inst_s {
	
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
typedef struct inst_s *inst_ptr;
typedef struct inst_s inst_t[1];

// A witness to an instance to a proof. If the prover is able to create a valid response to a challenge
// for the witness, the instance is consistent with the description of the proof (with overwhelming probability).
typedef void* witness_t[1];

// A challenge that demonstrates an instance/witness pair is probably consistent when a 
// correct response is given.
typedef mpz_t challenge_t;

#endif // ZKP_TYPES_H_
