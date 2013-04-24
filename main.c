#include <stdio.h>
#include "zkp.h"

int main() {
	pairing_t pairing;
	
	FILE* fparam = fopen("a.param", "rb");
	char param[1024];
	size_t count = fread(param, 1, 1024, fparam);
	fclose(fparam);
	if (!count) pbc_die("input error");
	pairing_init_set_buf(pairing, param, count);
	
	// Setup field.
	element_t g;
	element_t h;
	element_init_G1(g, pairing);
	element_init_G1(h, pairing);
	element_random(g);
	element_random(h);
	
	// Describe proof (prover and verifier).
	proof_t proof;
	proof_init(proof, pairing->Zr, pairing->G1, g, h);
	
	var_t p = var_secret(proof);
	var_t q = var_secret(proof);
	var_t m = var_public(proof);
	require_mul(proof, m, p, q);
	require_wsum_zero_3(proof, 1, m, 1, p, 1, q);
	
	// Create a challenge (constant for demonstration purposes).
	element_t challenge;
	element_init(challenge, proof->Z_type->field);
	element_set_si(challenge, 1000001);
	
	// Create an instance of the proof (prover).
	inst_t pinst;
	inst_init_prover(proof, pinst);
	inst_var_set_si(proof, pinst, p, -2);
	inst_var_set_si(proof, pinst, q, -2);
	inst_var_set_si(proof, pinst, m, 4);
	inst_update(proof, pinst);
	
	// Create a witness for the proof (prover).
	data_ptr pclaim_secret = new((type_ptr)&proof->claim_secret_type);
	data_ptr pclaim_public = new((type_ptr)&proof->claim_public_type);
	data_ptr presponse = new((type_ptr)&proof->response_type);
	claim_gen(proof, pinst, pclaim_secret, pclaim_public);
	response_gen(proof, pinst, pclaim_secret, challenge, presponse);
	
	// Prepare a message for the verifier (prover).
	FILE* pmessage = fopen("message.dat", "w+b");
	inst_var_write(proof, pinst, m, pmessage);
	inst_commitments_write(proof, pinst, pmessage);
	write((type_ptr)&proof->claim_public_type, pclaim_public, pmessage);
	write((type_ptr)&proof->response_type, presponse, pmessage);
	fclose(pmessage);
	
	// Begin reading the message (verifier).
	FILE* vmessage = fopen("message.dat", "rb");
	
	// Create an instance of the proof (verifier)
	inst_t vinst;
	inst_init_verifier(proof, vinst);
	inst_var_read(proof, vinst, m, vmessage);
	inst_commitments_read(proof, vinst, vmessage);
	inst_update(proof, vinst);
	
	// Read witness (verifier)
	data_ptr vclaim_public = new((type_ptr)&proof->claim_public_type);
	data_ptr vresponse = new((type_ptr)&proof->response_type);
	read((type_ptr)&proof->claim_public_type, vclaim_public, vmessage);
	read((type_ptr)&proof->response_type, vresponse, vmessage);
	fclose(vmessage);
	
	// Verify (verifier).	
	if (response_verify(proof, vinst, vclaim_public, challenge, vresponse)) {
		printf("Verification success.\n");
	} else {
		printf("Verification failure.\n");
	}
	
	getchar();
	return 0;
}
