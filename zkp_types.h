#ifndef ZKP_TYPES_H_
#define ZKP_TYPES_H_

typedef struct computation_s *computation_ptr;
typedef struct block_s *block_ptr;

// Describes a zero-knowledge proof.
typedef struct proof_s *proof_ptr;
typedef struct proof_s {

	// The type for elements used as values in this proof.
	element_type_t Z_type;
		
	// The type for elements used for commitments in this proof.
	element_type_t G_type;
	
	// The types for witness data passed by this proof.
	struct multi_type_s {
		type_t base;
		type_ptr (*for_block)(block_ptr);
		proof_ptr proof;
	} inst_type, claim_secret_type, claim_public_type, response_type;
	
	// The g element for this proof, used for computing commitments.
	element_t g;
	
	// The h element for this proof, used for computing commitments.
	element_t h;
	
	// The number of secret variables in this proof.
	int num_secret;
	
	// The number of public variables in this proof.
	int num_public;
	
	// The first computation for this proof.
	computation_ptr first_computation;
	
	// The last computation for this proof.
	computation_ptr last_computation;
	
	// The first block for this proof.
	block_ptr first_block;
	
} proof_t[1];

// A reference to a proof variable, which may either be secret (set by the 
// prover on each instance and kept unknown to the verifier) or public (set
// consistently between the prover and verifier for each instance).
typedef unsigned long var_t;

// A specific instance of a proof, containing the values of all known variables.
typedef struct inst_s *inst_ptr;
typedef struct inst_s {
	
	// The values of the secret variables. This will be NULL for the verifier.
	element_t *secret_values;
	
	// The openings for the secret variables. This will be NULL for the verifier.
	element_t *secret_openings;
	
	// The commitments for the secret variables. The verifier must get these from the
	// prover.
	element_t *secret_commitments;
	
	// The values of the public variables.
	element_t *public_values;
	
	// Block-dependent instance data.
	data_ptr block_data;
	
} inst_t[1];

// A challenge that demonstrates an instance/witness pair is probably consistent when a 
// correct response is given.
typedef element_t challenge_t;

#endif // ZKP_TYPES_H_
