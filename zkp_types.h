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
	
	// The (integer) field that contains the elements used for values in this proof.
	field_ptr Z;
	
	// The field that contains the elements used for commitments in this proof.
	field_ptr G;
	
	// The g element for this proof, used for computing commitments.
	element_t g;
	
	// The h element for this proof, used for computing commitments.
	element_t h;
	
	// The first computation for this proof.
	struct computation_s *first_computation;
	
	// The last computation for this proof.
	struct computation_s *last_computation;
	
	// The first block for this proof.
	struct block_s *first_block;
	
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
	element_t *secret_values;
	
	// The openings for the secret variables. This will be NULL for the verifier.
	element_t *secret_openings;
	
	// The commitments for the secret variables. The verifier must get these from the
	// prover.
	element_t *secret_commitments;
	
	// The values of the public variables.
	element_t *public_values;
};
typedef struct inst_s *inst_ptr;
typedef struct inst_s inst_t[1];

// A witness to an instance to a proof. If the prover is able to create a valid response to a challenge
// for the witness, the instance is consistent with the description of the proof (with overwhelming probability).
typedef void* witness_t[1];

// A challenge that demonstrates an instance/witness pair is probably consistent when a 
// correct response is given.
typedef element_t challenge_t;

#endif // ZKP_TYPES_H_
