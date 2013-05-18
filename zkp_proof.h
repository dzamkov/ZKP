#ifndef ZKP_TYPES_H_
#define ZKP_TYPES_H_

typedef struct computation_s *computation_ptr;
typedef struct block_s *block_ptr;
typedef struct sig_scheme_s *sig_scheme_ptr;

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
	} supplement_type, claim_secret_type, claim_public_type, response_type;
	
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

// Initializes a proof, setting it to a default empty state.
void proof_init(proof_t proof, field_ptr Z, field_ptr G, element_t g, element_t h);

// Frees the space occupied by a proof.
void proof_clear(proof_t proof);

// A reference to a proof variable, which may either be secret (set by the 
// prover on each instance and kept unknown to the verifier) or public (set
// consistently between the prover and verifier for each instance).
typedef unsigned long var_t;

// A reference to a block-dependent supplement within an instance. Supplements provide
// information needed to perform certain proofs.
typedef size_t supplement_t;

// Declares a new secret variable in the given proof.
var_t var_secret(proof_t proof);

// Declares a new public variable in the given proof.
var_t var_public(proof_t proof);

// Defines a new constant variable in the given proof.
var_t var_const(proof_t proof, element_t value);
var_t var_const_mpz(proof_t proof, mpz_t value);
var_t var_const_si(proof_t proof, long int value);

// Requires a multiplicative relationship between the given product and factor variables in the given proof.
void require_mul(proof_t proof, var_t product, var_t factor_1, var_t factor_2);

// Requires that the values of all of the given variables are equivalent in the given proof.
void require_equal(proof_t proof, int count, /* var_t a, var_t b, */ ...);
void require_equal_many(proof_t proof, int count, var_t* vars);

// Requires an additive relationship between the given sum and addends variables in the given proof.
void require_sum(proof_t proof, var_t sum, var_t addend_1, var_t addend_2);

// Requires an additive relationship between the given difference, minuend and subtrahend variables in the given proof.
void require_dif(proof_t proof, var_t dif, var_t minuend, var_t subtrahend);

// Requires the weighted sum of the given variables to be zero in the given proof.
void require_wsum_zero(proof_t proof, int count, /* long a_coeff, var_t a, long b_coeff, var_t b, */ ...);
void require_wsum_zero_many(proof_t proof, int count, long* coeffs, var_t* vars);

// Requires a signature on a set of variables in the given proof.
void require_sig(proof_t proof, sig_scheme_ptr scheme, data_ptr public_key, supplement_t* sig, /* var_t a, var_t b, */ ...);
void require_sig_many(proof_t proof, sig_scheme_ptr scheme, data_ptr public_key, supplement_t* sig, var_t* vars);

// Indicates whether the given variable is secret.
int var_is_secret(var_t var);

// Indicates whether the given variable is public.
int var_is_public(var_t var);


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
	
	// Block-dependent supplementary instance data.
	data_ptr supplement_data;
	
} inst_t[1];

// Initializes a prover instance of a proof.
void inst_init_prover(proof_t proof, inst_t inst);

// Initializes a verifier instance of a proof.
void inst_init_verifier(proof_t proof, inst_t inst);

// Frees the space occupied by an instance of a proof.
void inst_clear(proof_t proof, inst_t inst);

// Sets the value of a variable in an instance of a proof. If the variable is
// secret, a random opening and corresponding commitment will automatically be
// generated.
void inst_var_set(proof_t proof, inst_t inst, var_t var, element_t value);
void inst_var_set_mpz(proof_t proof, inst_t inst, var_t var, mpz_t value);
void inst_var_set_si(proof_t proof, inst_t inst, var_t var, long int value);

// Retrieves the value of a variable in an instance of the given proof.
element_ptr inst_var_get(proof_t proof, inst_t inst, var_t var);

// Outputs the value of an instance variable to a stream.
void inst_var_write(proof_t proof, inst_t inst, var_t var, FILE* stream);

// Reads the value of an instance variable from a stream.
void inst_var_read(proof_t proof, inst_t inst, var_t var, FILE* stream);

// Sets the values of computed variables in an instance.
void inst_update(proof_t proof, inst_t inst);

// Returns a pointer to a supplement in an instance.
data_ptr inst_supplement(proof_t proof, inst_t inst, supplement_t supplement);

// Outputs all commitments for secret variables to a stream.
void inst_commitments_write(proof_t proof, inst_t inst, FILE* stream);

// Reads all commitments for secret variables from a stream.
void inst_commitments_read(proof_t proof, inst_t inst, FILE* stream);

// Creates a random claim for an instance of a proof. A succesful response to the claim
// with a randomly chosen challenge acts as a witness to the validity of the instance.
void claim_gen(proof_t proof, inst_t inst, data_ptr claim_secret, data_ptr claim_public);

// A challenge that demonstrates an instance/witness pair is probably consistent when a 
// correct response is given.
typedef element_t challenge_t;

// Creates a response to a claim for a given challenge.
void response_gen(proof_t proof, inst_t inst, data_ptr claim_secret, challenge_t challenge, data_ptr response);

// Verifies the consistency of a response, returning zero if it is invalid or some non-zero value if it is
// valid.
int response_verify(proof_t proof, inst_t inst, data_ptr claim_public, challenge_t challenge, data_ptr response);

#endif // ZKP_TYPES_H_
