#ifndef ZKP_INTERNAL_H_
#define ZKP_INTERNAL_H_

// Outputs an element to a stream, returning the number of bytes that were
// written, or 0, if an error occured.
size_t element_out_raw(FILE* stream, element_t element);

// Reads an element from a stream, returning the number of bytes that were
// read, or 0, if an error occured.
size_t element_inp_raw(element_t element, FILE* stream);

// Gets the index for the given variable.
long var_index(var_t var);

// A computational procedure for a proof that calculates the values of a subset of
// instance variables.
struct computation_s {
	void (*clear)(struct computation_s*);
	void (*apply)(struct computation_s* computation, proof_t, inst_t);
	struct computation_s *next;
};

// Inserts a computation into a proof.
void computation_insert(proof_t proof, int is_secret, struct computation_s *computation);

// Clears all computations in a proof.
void computations_clear(proof_t proof);

// Inserts a computation into a proof that assigns a constant value to a variable.
void computation_set(proof_t proof, var_t var, mpz_t value);
void computation_set_ui(proof_t proof, var_t var, unsigned long int value);
void computation_set_si(proof_t proof, var_t var, signed long int value);

// A procedure for a proof that verifies some relation between (possibly secret) variables.
struct block_s {
	void (*clear)(struct block_s*);
	void (*witness_init)(struct block_s*, proof_t, void*);
	void (*witness_clear)(struct block_s*, void*);
	void (*witness_claim_gen)(struct block_s*, void*, proof_t, inst_t);
	void (*witness_claim_write)(struct block_s*, void*, FILE*);
	void (*witness_claim_read)(struct block_s*, void*, FILE*);
	void (*witness_response_gen)(struct block_s*, void*, proof_t, inst_t, challenge_t);
	void (*witness_response_write)(struct block_s*, void*, FILE*);
	void (*witness_response_read)(struct block_s*, void*, FILE*);
	int (*witness_response_verify)(struct block_s*, void*, proof_t, inst_t, challenge_t);
	struct block_s *next;
	size_t witness_size;
};

// Inserts a block into a proof.
void block_insert(proof_t proof, struct block_s *block);

// Clears all blocks in a proof.
void blocks_clear(proof_t proof);

// Generates witness information for all blocks in a proof.
void blocks_generate(proof_t proof, inst_t inst, witness_t witness, FILE* data);

// Inserts a block into a proof that verifies a product relationship between three secret variables.
void block_product(proof_t proof, var_t product, var_t factor_1, var_t factor_2);

#endif // ZKP_INTERNAL_H_
