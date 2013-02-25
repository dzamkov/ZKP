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
	
	var_t p = new_secret(proof);
	var_t q = new_secret(proof);
	var_t m = new_public(proof);
	
	// Create an instance of the proof (prover)
	inst_t pinst;
	inst_init_prover(proof, pinst);
	inst_set_ui(proof, pinst, p, 137);
	inst_set_ui(proof, pinst, q, 173);
	inst_set_ui(proof, pinst, m, 17473);
	inst_update(proof, pinst);
	
	// Create an instance of the proof (verifier)
	inst_t vinst;
	inst_init_verifier(proof, vinst);
	inst_set_ui(proof, vinst, m, 17473);
	inst_update(proof, vinst);
	
	gmp_printf("Prover: P = %Zd, Q = %Zd, M = %Zd\n",
				inst_get(proof, pinst, p),
				inst_get(proof, pinst, q),
				inst_get(proof, pinst, m));
				
	gmp_printf("Verifier: M = %Zd\n", inst_get(proof, vinst, m));
	
	getchar();
	return 0;
}
