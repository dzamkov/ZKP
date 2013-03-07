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

// Outputs the value of an instance variable to a stream, returning the number of bytes that were
// written, or 0, if an error occured.
size_t inst_var_out_raw(FILE* stream, proof_t proof, inst_t inst, var_t var);

// Reads the value of an instance variable from a stream, returning the number of bytes that were
// read, or 0, if an error occured.
size_t inst_var_inp_raw(proof_t proof, inst_t inst, var_t var, FILE* stream);

// Sets the values of computed variables in an instance.
void inst_update(proof_t proof, inst_t inst);

// Outputs the commitment for a secret instance variable to a stream, returning the number of bytes that
// were written, or 0, if an error occured.
size_t inst_commitment_out_raw(FILE* stream, proof_t proof, inst_t inst, var_t var);

// Reads a commitment for a secret instance variable from a stream, returning the number of bytes that
// were read, or 0, if an error occured.
size_t inst_commitment_inp_raw(proof_t proof, inst_t inst, var_t var, FILE* stream);

// Outputs commitments for all secret instance variables to a stream, returning the number of bytes that
// were written, or 0, if an error occured.
size_t inst_commitments_out_raw(FILE* stream, proof_t proof, inst_t inst);

// Reads commitments for all secret instance variable from a stream, returning the number of bytes that
// were read, or 0, if an error occured.
size_t inst_commitments_inp_raw(proof_t proof, inst_t inst, FILE* stream);


#endif // ZKP_H_
