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
	proof_init(proof, g, h);
	
	var_t p = var_secret(proof);
	var_t q = var_secret(proof);
	var_t m = var_public(proof);
	block_product(proof, m, p, q);
	
	// Create an instance of the proof (prover).
	inst_t pinst;
	inst_init_prover(proof, pinst);
	inst_var_set_ui(proof, pinst, p, 137);
	inst_var_set_ui(proof, pinst, q, 173);
	inst_var_set_ui(proof, pinst, m, 17473);
	inst_update(proof, pinst);
	
	// Create a witness for the proof (prover).
	witness_t pwitness;
	witness_init(proof, pwitness);
	
	// Prepare a message for the verifier (prover).
	FILE* pmessage = fopen("message.dat", "w+b");
	inst_var_write(proof, pinst, m, pmessage);
	inst_commitments_write(proof, pinst, pmessage);
	fclose(pmessage);
	
	// Begin reading the message (verifier).
	FILE* vmessage = fopen("message.dat", "rb");
	
	// Create an instance of the proof (verifier)
	inst_t vinst;
	inst_init_verifier(proof, vinst);
	inst_var_read(proof, vinst, m, vmessage);
	inst_commitments_read(proof, vinst, vmessage);
	inst_update(proof, vinst);
	
	fclose(vmessage);
	
	printf("Values:\n");
	gmp_printf("\tProver: P = %Zd, Q = %Zd, M = %Zd\n",
		inst_var_get(proof, pinst, p),
		inst_var_get(proof, pinst, q),
		inst_var_get(proof, pinst, m));
				
	gmp_printf("\tVerifier: M = %Zd\n", inst_var_get(proof, vinst, m));
	
	printf("Commitments:\n");
	element_printf("\tProver:\n\t\tP = %B\n\t\tQ = %B\n",
		pinst->secret_commitments[0], pinst->secret_commitments[1]);
	element_printf("\tVerifier:\n\t\tP = %B\n\t\tQ = %B\n",
		vinst->secret_commitments[0], vinst->secret_commitments[1]);
	
	getchar();
	return 0;
}
