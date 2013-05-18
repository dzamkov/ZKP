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
	
	// Create a signature scheme
	sig_scheme_t scheme;
	sig_scheme_init(scheme, 3, pairing, g);
	data_ptr secret_key = new((type_ptr)scheme->secret_key_type);
	data_ptr public_key = new((type_ptr)scheme->public_key_type);
	sig_key_setup(scheme, secret_key, public_key);
	
	// Describe proof (prover and verifier).
	proof_t proof;
	proof_init(proof, pairing->Zr, pairing->G1, g, h);
	
	supplement_t sig_supplement;
	var_t p = var_secret(proof);
	var_t q = var_secret(proof);
	var_t m = var_public(proof);
	require_mul(proof, m, p, q);
	require_sig(proof, scheme, public_key, &sig_supplement, p, q, m);
	
	// Create a challenge (constant for demonstration purposes).
	element_t challenge;
	element_init(challenge, proof->Z_type->field);
	element_set_si(challenge, 1000001);
	
	// Create a signature for the supplement
	element_t message[3];
	element_init(message[0], scheme->Z_type->field); element_set_si(message[0], 3);
	element_init(message[1], scheme->Z_type->field); element_set_si(message[1], 4);
	element_init(message[2], scheme->Z_type->field); element_set_si(message[2], 12);

	data_ptr sig = new((type_ptr)scheme->sig_type);
	sig_sign(scheme, secret_key, sig, message);
	
	// Create an instance of the proof (prover).
	inst_t pinst;
	mpz_t p_val; mpz_init(p_val);
	mpz_t q_val; mpz_init(q_val);
	mpz_t m_val; mpz_init(m_val);
	printf("p = "); gmp_scanf("%Zd", p_val);
	printf("q = "); gmp_scanf("%Zd", q_val);
	printf("m = "); gmp_scanf("%Zd", m_val);
	
	inst_init_prover(proof, pinst);
	inst_var_set_mpz(proof, pinst, p, p_val);
	inst_var_set_mpz(proof, pinst, q, q_val);
	inst_var_set_mpz(proof, pinst, m, m_val);
	copy((type_ptr)scheme->sig_type, inst_supplement(proof, pinst, sig_supplement), sig);
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
	getchar();
	return 0;
}
