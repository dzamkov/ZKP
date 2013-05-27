#ifndef ZKP_INTERNAL_H_
#define ZKP_INTERNAL_H_

// Finds two non-negative integers whose squares sum to the given 
// prime (congruent to 1 mod 4). This is always possible due to Fermat's 
// theorem on sums of two squares. Returns false if the precondition is
// not met (such as when n is a probable prime, but not prime).
int mpz_decompose_prime(mpz_t a, mpz_t b, mpz_t n);

// Finds four non-negative integers whose squares su to the given 
// non-negative integer. This is always possible due to the
// Lagrange four square theorem.
void mpz_decompose(mpz_t a, mpz_t b, mpz_t c, mpz_t d, mpz_t n);

// Gets the index for the given variable.
long var_index(var_t var);

// Returns a variable index for a secret variable that is equivalent to the given
// variable.
long var_secret_index(proof_t proof, var_t var);

// A computational procedure for a proof that calculates the values of a subset of
// instance variables.
typedef struct computation_s *computation_ptr;
typedef struct computation_s {
	void (*clear)(computation_ptr);
	void (*apply)(computation_ptr, proof_t, inst_t);
	int is_secret;
	computation_ptr next;
} computation_t[1];

// Inserts a computation into a proof.
void computation_insert(proof_t proof, computation_ptr computation);

// Clears all computations in a proof.
void computations_clear(proof_t proof);

// Inserts a computation into a proof that assigns a constant value to a variable.
void computation_set(proof_t proof, var_t var, element_t value);
void computation_set_mpz(proof_t proof, var_t var, mpz_t value);
void computation_set_si(proof_t proof, var_t var, long int value);

// Inserts a computation into a proof that assigns one variable to another.
void computation_mov(proof_t proof, var_t dest, var_t src);

// A procedure for a proof that verifies some relation between (possibly secret) variables.
typedef struct block_s *block_ptr;
typedef struct block_s {
	void (*clear)(block_ptr);
	void (*claim_gen)(block_ptr, proof_t, inst_t, data_ptr, data_ptr);
	void (*response_gen)(block_ptr, proof_t, inst_t, data_ptr, challenge_t, data_ptr);
	int (*response_verify)(block_ptr, proof_t, inst_t, data_ptr, challenge_t, data_ptr);
	type_ptr supplement_type;
	type_ptr claim_secret_type;
	type_ptr claim_public_type;
	type_ptr response_type;
	block_ptr next;
} block_t[1];

// Inserts a block into a proof.
void block_insert(proof_t proof, block_ptr block);

// Clears all blocks in a proof.
void blocks_clear(proof_t proof);

// Inserts a block into a proof that verifies that a secret variable and a public variable are equivalent.
void block_equals_public(proof_t proof, long secret_index, long public_index);

// Inserts a block into a proof that verifies a product relationship between three secret variables.
void block_product(proof_t proof, long product_index, long factor_1_index, long factor_2_index);

#endif // ZKP_INTERNAL_H_
