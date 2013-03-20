#ifndef ZKP_H_
#define ZKP_H_

#include <pbc.h>
#include "zkp_types.h"

// Initializes a proof, setting it to a default empty state.
void proof_init(proof_t proof, element_t g, element_t h);

// Frees the space occupied by a proof.
void proof_clear(proof_t proof);

// Declares a new secret variable in the given proof.
var_t var_secret(proof_t proof);

// Declares a new public variable in the given proof.
var_t var_public(proof_t proof);

// Defines a new constant variable in the given proof.
var_t var_const(proof_t proof, mpz_t value);
var_t var_const_ui(proof_t proof, unsigned long int value);
var_t var_const_si(proof_t proof, signed long int value);

// Indicates whether the given variable is secret.
int var_is_secret(var_t var);

// Indicates whether the given variable is public.
int var_is_public(var_t var);

// Initializes a prover instance of a proof.
void inst_init_prover(proof_t proof, inst_t inst);

// Initializes a verifier instance of a proof.
void inst_init_verifier(proof_t proof, inst_t inst);

// Frees the space occupied by an instance of a proof.
void inst_clear(proof_t proof, inst_t inst);

// Sets the value of a variable in an instance of a proof. If the variable is
// secret, a random opening and corresponding commitment will automatically be
// generated.
void inst_var_set(proof_t proof, inst_t inst, var_t var, mpz_t value);
void inst_var_set_ui(proof_t proof, inst_t inst, var_t var, unsigned long int value);
void inst_var_set_si(proof_t proof, inst_t inst, var_t var, signed long int value);

// Retrieves the value of a variable in an instance of the given proof.
mpz_ptr inst_var_get(proof_t proof, inst_t inst, var_t var);

// Outputs the value of an instance variable to a stream.
void inst_var_write(proof_t proof, inst_t inst, var_t var, FILE* stream);

// Reads the value of an instance variable from a stream.
void inst_var_read(proof_t proof, inst_t inst, var_t var, FILE* stream);

// Sets the values of computed variables in an instance.
void inst_update(proof_t proof, inst_t inst);

// Outputs all commitments for secret variables to a stream.
void inst_commitments_write(proof_t proof, inst_t inst, FILE* stream);

// Reads all commitments for secret variables from a stream.
void inst_commitments_read(proof_t proof, inst_t inst, FILE* stream);

// Initializes a witness for a proof.
void witness_init(proof_t proof, witness_t witness);

// Frees the space occupied by a witness of a proof.
void witness_clear(proof_t proof, witness_t witness);

// Generates a random claim for a witness of a proof. This is performed by the prover before
// the challenge is known.
void witness_claim_gen(proof_t proof, inst_t inst, witness_t witness);

// Outputs the public claim information in a witness to a stream.
void witness_claim_write(proof_t proof, witness_t witness, FILE* stream);

// Reads the public claim information from a stream into a witness.
void witness_claim_read(proof_t proof, witness_t witness, FILE* stream);

// Generates a response for a witness of a proof. This is performed by the prover after the
// challenge is known.
void witness_reponse_gen(proof_t proof, inst_t inst, witness_t witness, challenge_t challenge);

// Outputs the response information in a witness to a stream.
void witness_response_write(proof_t proof, witness_t witness, FILE* stream);

// Reads the response information from a stream into a witness.
void witness_response_read(proof_t proof, witness_t witness, FILE* stream);

// Verifies that the response information in the given witness is consistent with the given instance
// and challenge, returning zero otherwise. This is performed by the verifier to check if a witness
// is valid.
int witness_response_verify(proof_t proof, inst_t inst, witness_t witness, challenge_t challenge);

#endif // ZKP_H_
