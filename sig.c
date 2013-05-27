#include <pbc.h>
#include "zkp_io.h"
#include "zkp_sig.h"
#include "zkp_proof.h"
#include "zkp_internal.h"

void sig_scheme_init(sig_scheme_t scheme, int n, pairing_ptr pairing, element_t g) {
	element_type_init(scheme->Z_type, pairing->Zr);
	element_type_init(scheme->G_type, pairing->G1);
	element_type_init(scheme->T_type, pairing->GT);
	array_type_init(scheme->secret_key_type, (type_ptr)scheme->Z_type, n + 1);
	array_type_init(scheme->public_key_type, (type_ptr)scheme->G_type, n + 1);
	array_type_init(scheme->sig_type, (type_ptr)scheme->G_type, n * 2 + 1);
	element_init(scheme->g, scheme->G_type->field); element_set(scheme->g, g);
	scheme->n = n;
	scheme->pairing = pairing;
}

void sig_scheme_clear(sig_scheme_t scheme) {
	element_free(scheme->g);
}

void sig_key_setup(sig_scheme_t scheme, data_ptr secret_key, data_ptr public_key) {
	int i; int m = scheme->n + 1;
	for (i = 0; i < m; i++) {
		element_ptr t = get_element(scheme->Z_type, get_item(scheme->secret_key_type, secret_key, i));
		element_ptr T = get_element(scheme->G_type, get_item(scheme->public_key_type, public_key, i));
	
		// T = t ^ x
		element_random(t);
		element_pow_zn(T, scheme->g, t);
	}
}

void sig_sign(sig_scheme_t scheme, data_ptr secret_key, data_ptr sig, element_t message[]) {
	int i; int n = scheme->n; int l = n - 1;
	element_ptr x = get_element(scheme->Z_type, get_item(scheme->secret_key_type, secret_key, 0));
	element_ptr y = get_element(scheme->Z_type, get_item(scheme->secret_key_type, secret_key, 1));
	element_ptr a = get_element(scheme->G_type, get_item(scheme->sig_type, sig, 0));
	element_ptr b = get_element(scheme->G_type, get_item(scheme->sig_type, sig, 1));
	element_ptr c = get_element(scheme->G_type, get_item(scheme->sig_type, sig, 2));

	// xy = x * y
	element_t xy; element_init(xy, scheme->Z_type->field);
	element_mul(xy, x, y);

	// b = a ^ y
	element_random(a);
	element_pow_zn(b, a, y);

	// c = a ^ (x + x * y * m_0)
	element_t e; element_init(e, scheme->Z_type->field);
	element_mul(e, xy, message[0]);
	element_add(e, e, x);
	element_pow_zn(c, a, e);
	
	element_t f; element_init(f, scheme->G_type->field);
	for (i = 0; i < l; i++) {
		element_ptr z = get_element(scheme->Z_type, get_item(scheme->secret_key_type, secret_key, 2 + i));
		element_ptr A = get_element(scheme->G_type, get_item(scheme->sig_type, sig, 3 + i));
		element_ptr B = get_element(scheme->G_type, get_item(scheme->sig_type, sig, 3 + (n - 1) + i));
		
		// A = a ^ z
		element_pow_zn(A, a, z);
		
		// B = A ^ y
		element_pow_zn(B, A, y);
		
		// C *= A ^ (x * y * m_{i + 1})
		element_mul(e, xy, message[1 + i]);
		element_pow_zn(f, A, e);
		element_mul(c, c, f);
	}
	
	element_clear(xy);
	element_clear(e);
	element_clear(f);
}

int sig_verify(sig_scheme_t scheme, data_ptr public_key, data_ptr sig, element_t message[]) {
	int i; int n = scheme->n; int l = n - 1;
	element_ptr X = get_element(scheme->G_type, get_item(scheme->public_key_type, public_key, 0));
	element_ptr Y = get_element(scheme->G_type, get_item(scheme->public_key_type, public_key, 1));
	element_ptr a = get_element(scheme->G_type, get_item(scheme->sig_type, sig, 0));
	element_ptr b = get_element(scheme->G_type, get_item(scheme->sig_type, sig, 1));
	element_ptr c = get_element(scheme->G_type, get_item(scheme->sig_type, sig, 2));
	
	element_t left; element_init(left, scheme->T_type->field);
	element_t right; element_init(right, scheme->T_type->field);
	element_t temp; element_init(temp, scheme->T_type->field);
	
	// Verify <Y, a> = <g, b>
	int result = 1;
	pairing_apply(left, Y, a, scheme->pairing);
	pairing_apply(right, scheme->g, b, scheme->pairing);
	if (element_cmp(left, right)) {
		result = 0;
		goto end;
	}
	
	for (i = 0; i < l; i++) {
		element_ptr Z = get_element(scheme->G_type, get_item(scheme->public_key_type, public_key, 2 + i));
		element_ptr A = get_element(scheme->G_type, get_item(scheme->sig_type, sig, 3 + i));
		element_ptr B = get_element(scheme->G_type, get_item(scheme->sig_type, sig, 3 + (n - 1) + i));
		
		// Verify <Z, a> = <g, A>
		pairing_apply(left, Z, a, scheme->pairing);
		pairing_apply(right, scheme->g, A, scheme->pairing);
		if (element_cmp(left, right)) {
			result = 0;
			goto end;
		}
		
		// Verify <Y, A> = <g, B>
		pairing_apply(left, Y, A, scheme->pairing);
		pairing_apply(right, scheme->g, B, scheme->pairing);
		if (element_cmp(left, right)) {
			result = 0;
			goto end;
		}
	}
	
	// Verify <X, a> * <X, b> ^ m_0 * <X, B_0> ^ m_1 * <X, B_1> ^ m_2 * ... = <g, c>
	pairing_pp_t pp; pairing_pp_init(pp, X, scheme->pairing);
	pairing_pp_apply(left, a, pp);
	pairing_pp_apply(temp, b, pp);
	element_pow_zn(temp, temp, message[0]);
	element_mul(left, left, temp);
	for (i = 0; i < l; i++) {
		element_ptr B = get_element(scheme->G_type, get_item(scheme->sig_type, sig, 3 + (n - 1) + i));
		pairing_pp_apply(temp, B, pp);
		element_pow_zn(temp, temp, message[1 + i]);
		element_mul(left, left, temp);
	}
	pairing_pp_clear(pp);
	pairing_apply(right, scheme->g, c, scheme->pairing);
	result = !element_cmp(left, right);
	
end:
	element_clear(left);
	element_clear(right);
	element_clear(temp);
	return result;
}


/***************************************************
* sig
*
* Verifies the possession of a signature on a set
* of commitments.
****************************************************/

typedef struct block_sig_s *block_sig_ptr;
typedef struct block_sig_s {
	block_t base;
	array_type_t message_type;
	array_type_t message_commitment_type;
	composite_type_t Zx_type;
	composite_type_t Gx_type;
	composite_type_t claim_secret_type;
	composite_type_t claim_public_type;
	sig_scheme_ptr scheme;
	data_ptr public_key;
	supplement_t sig;
	long *indices;
} block_sig_t[1];

// e    	= challenge
// <x, y>	= (bilinear pairing of x and y)
// g     	= scheme->g

// x  	= x in secret key
// y    = y in secret key
// z_#	= z_# in secret key

// X  	= X in public key
// Y  	= Y in public key
// Z_#	= Z_# in public key

// p, q	:: (scheme->Z_type->field)
// a   	= (a in sig) ^ q
// A_# 	= (A_# in sig) ^ q
// b   	= (b in sig) ^ q
// B_# 	= (B_# in sig) ^ q
// c   	= (c in sig) ^ (p * q)

// m_#  	= inst->secret_values[indices[#]]
// o_m_#	= inst->secret_openings[indices[#]]
// C_m_#	= inst->secret_commitments[indices[#]]

// Vx   	= <X, a>	= <g, a> ^ (x * q)
// Vxy  	= <X, b>	= <g, a> ^ (x * y * q)
// Vxy_#	= <X, B_#>	= <g, a> ^ (x * y * z_# * q)
// Vs   	= <g, c>	= (Vx * Vxy ^ m_0 * Vxy_1 ^ m_1 * Vxy_2 ^ m_2 * ...) ^ p

// <Z_#, a>	= <g, A_#>	= <g, a> ^ (z_# * q)
// <Y, a>  	= <g, b>  	= <g, a> ^ (y * q)
// <Y, A_#>	= <g, B_#>	= <g, a> ^ (y * z_# * q)

// Vq	= Vx * Vxy ^ m_0 * Vxy_1 ^ m_1 * Vxy_2 ^ m_2 * ...
// Vs	= Vq ^ p

// [r_p, r_0, o_r_0, r_1, o_r_1, ...]	= (Vq ^ r_p, Vxy ^ r_0 * Vxy_1 ^ r_1 * ..., g ^ r_0 * h ^ o_r_0, g ^ r_1 * h ^ o_r_1, ...)
// [p, m_0, o_m_0, m_1, o_m_1, ...]  	= (Vs, Vq / Vx, C_m_0, C_m_1, ...)

void _sig_clear(block_ptr);
void _sig_claim_gen(block_ptr, proof_t, inst_t, data_ptr, data_ptr);
void _sig_response_gen(block_ptr, proof_t, inst_t, data_ptr, challenge_t, data_ptr);
int _sig_response_verify(block_ptr, proof_t, inst_t, data_ptr, challenge_t, data_ptr);
block_sig_ptr block_sig_base(proof_t proof, sig_scheme_ptr scheme, data_ptr public_key) {
	block_sig_ptr self = (block_sig_ptr)pbc_malloc(sizeof(block_sig_t));
	array_type_init(self->message_type, (type_ptr)proof->Z_type, scheme->n * 2);
	array_type_init(self->message_commitment_type, (type_ptr)proof->G_type, scheme->n);
	composite_type_init(self->Zx_type, 2, (type_ptr)scheme->Z_type, (type_ptr)self->message_type);
	composite_type_init(self->Gx_type, 3, (type_ptr)scheme->T_type, (type_ptr)scheme->T_type, (type_ptr)self->message_commitment_type);
	composite_type_init(self->claim_secret_type, 3, (type_ptr)scheme->Z_type, (type_ptr)scheme->sig_type, (type_ptr)self->Zx_type);
	composite_type_init(self->claim_public_type, 3, (type_ptr)scheme->T_type, (type_ptr)scheme->sig_type, (type_ptr)self->Gx_type);
	self->base->clear = &_sig_clear;
	self->base->claim_gen = &_sig_claim_gen;
	self->base->response_gen = &_sig_response_gen;
	self->base->response_verify = &_sig_response_verify;
	self->base->supplement_type = (type_ptr)scheme->sig_type;
	self->base->claim_secret_type = (type_ptr)self->claim_secret_type;
	self->base->claim_public_type = (type_ptr)self->claim_public_type;
	self->base->response_type = (type_ptr)self->Zx_type;
	self->scheme = scheme;
	self->public_key = public_key;
	self->sig = proof->supplement_type.base->size;
	self->indices = (long*)pbc_malloc(sizeof(long) * scheme->n);
	block_insert(proof, (block_ptr)self);
	return self;
}

void _sig_clear(block_ptr block) {
	block_sig_ptr self = (block_sig_ptr)block;
	composite_type_clear(self->Zx_type);
	composite_type_clear(self->Gx_type);
	composite_type_clear(self->claim_secret_type);
	composite_type_clear(self->claim_public_type);
	pbc_free(self->indices);
	pbc_free(self);
}

void _sig_claim_gen(block_ptr block, proof_t proof, inst_t inst, data_ptr claim_secret, data_ptr claim_public) {
	block_sig_ptr self = (block_sig_ptr)block;
	sig_scheme_ptr scheme = self->scheme;
	int i; int n = scheme->n; int l = n - 1;
	data_ptr original_sig = inst_supplement(proof, inst, self->sig);
	element_ptr p = get_element(scheme->Z_type, get_part(self->claim_secret_type, claim_secret, 0));
	element_ptr Vq = get_element(scheme->T_type, get_part(self->claim_public_type, claim_public, 0));
	data_ptr blinded_sig_1 = get_part(self->claim_secret_type, claim_secret, 1);
	data_ptr blinded_sig_2 = get_part(self->claim_public_type, claim_public, 1);
	
	data_ptr Zx = get_part(self->claim_secret_type, claim_secret, 2);
	element_ptr r_p = get_element(scheme->Z_type, get_part(self->Zx_type, Zx, 0));
	data_ptr r_message = get_part(self->Zx_type, Zx, 1);
	
	data_ptr Gx = get_part(self->claim_public_type, claim_public, 2);
	element_ptr R_Vs = get_element(scheme->T_type, get_part(self->Gx_type, Gx, 0));
	element_ptr R_Vq = get_element(scheme->T_type, get_part(self->Gx_type, Gx, 1));
	data_ptr R_message = get_part(self->Gx_type, Gx, 2);
	
	// Create a blinded signature by exponentiating all parts of the original signature by q.
	element_t q; element_init(q, scheme->Z_type->field);
	element_random(q);
	for (i = 0; i < 2 * n + 1; i++) {
		element_ptr To = get_element(scheme->G_type, get_item(scheme->sig_type, original_sig, i));
		element_ptr Tb = get_element(scheme->G_type, get_item(scheme->sig_type, blinded_sig_1, i));
		
		// Tb = To ^ q
		element_pow_zn(Tb, To, q);
	}
	element_clear(q);
	
	// c := c ^ p
	element_ptr c = get_element(scheme->G_type, get_item(scheme->sig_type, blinded_sig_1, 2));
	element_random(p);
	element_pow_zn(c, c, p);
	copy((type_ptr)scheme->sig_type, blinded_sig_2, blinded_sig_1);
	
	// R_# = g ^ r_# * h ^ o_r_#
	for (i = 0; i < n; i++) {
		element_ptr r = get_element(proof->Z_type, get_item(self->message_type, r_message, i));
		element_ptr o_r = get_element(proof->Z_type, get_item(self->message_type, r_message, n + i));
		element_ptr R = get_element(proof->G_type, get_item(self->message_commitment_type, R_message, i));
		element_random(r);
		element_random(o_r);
		element_pow2_zn(R, proof->g, r, proof->h, o_r);
	}
	
	// Vq = Vx * Vxy ^ m_0 * Vxy_1 ^ m_1 * Vxy_2 ^ m_2 * ...
	// R_Vq = Vxy ^ r_0 * Vxy_1 ^ r_1 * Vxy_2 ^ r_2 * ...
	element_ptr a = get_element(scheme->G_type, get_item(scheme->sig_type, blinded_sig_1, 0));
	element_ptr b = get_element(scheme->G_type, get_item(scheme->sig_type, blinded_sig_1, 1));
	element_ptr X = get_element(scheme->G_type, get_item(scheme->public_key_type, self->public_key, 0));
	element_ptr r_0 = get_element(proof->Z_type, get_item(self->message_type, r_message, 0));
	
	pairing_pp_t pp; pairing_pp_init(pp, X, scheme->pairing);
	element_t temp; element_init(temp, scheme->T_type->field);
	element_t temp_R; element_init(temp_R, scheme->T_type->field);
	
	pairing_pp_apply(Vq, a, pp);
	pairing_pp_apply(temp, b, pp);
	element_pow_zn(R_Vq, temp, r_0);
	element_pow_zn(temp, temp, inst->secret_values[self->indices[0]]);
	element_mul(Vq, Vq, temp);
	
	for (i = 0; i < l; i++) {
		element_ptr B = get_element(scheme->G_type, get_item(scheme->sig_type, blinded_sig_1, 3 + (n - 1) + i));
		element_ptr r = get_element(proof->Z_type, get_item(self->message_type, r_message, 1 + i));
		
		pairing_pp_apply(temp, B, pp);
		element_pow_zn(temp_R, temp, r);
		element_mul(R_Vq, R_Vq, temp_R);
		element_pow_zn(temp, temp, inst->secret_values[self->indices[1 + i]]);
		element_mul(Vq, Vq, temp);
	}
	pairing_pp_clear(pp);
	element_clear(temp);
	element_clear(temp_R);
	
	// R_Vs = Vq ^ r_p
	element_random(r_p);
	element_pow_zn(R_Vs, Vq, r_p);
}

void _sig_response_gen(block_ptr block, proof_t proof, inst_t inst, data_ptr claim_secret, challenge_t challenge, data_ptr response) {
	block_sig_ptr self = (block_sig_ptr)block;
	sig_scheme_ptr scheme = self->scheme;
	int i; int n = scheme->n;
	element_ptr p = get_element(scheme->Z_type, get_part(self->claim_secret_type, claim_secret, 0));
	data_ptr Zx = get_part(self->claim_secret_type, claim_secret, 2);
	element_ptr r_p = get_element(scheme->Z_type, get_part(self->Zx_type, Zx, 0));
	element_ptr x_p = get_element(scheme->Z_type, get_part(self->Zx_type, response, 0));
	data_ptr r_message = get_part(self->Zx_type, Zx, 1);
	data_ptr x_message = get_part(self->Zx_type, response, 1);
	
	// x_p = e * p + r_p
	element_mul(x_p, challenge, p);
	element_add(x_p, x_p, r_p);
	
	for (i = 0; i < n; i++) {
		element_ptr r = get_element(proof->Z_type, get_item(self->message_type, r_message, i));
		element_ptr o_r = get_element(proof->Z_type, get_item(self->message_type, r_message, n + i));
		element_ptr x = get_element(proof->Z_type, get_item(self->message_type, x_message, i));
		element_ptr o_x = get_element(proof->Z_type, get_item(self->message_type, x_message, n + i));
		
		// x_# = e * m_# + r_#
		element_mul(x, challenge, inst->secret_values[self->indices[i]]);
		element_add(x, x, r);
		
		// o_x_# = e * o_m_# + o_r_#
		element_mul(o_x, challenge, inst->secret_openings[self->indices[i]]);
		element_add(o_x, o_x, o_r);
	}
}

int _sig_response_verify(block_ptr block, proof_t proof, inst_t inst, data_ptr claim_public, challenge_t challenge, data_ptr response) {
	block_sig_ptr self = (block_sig_ptr)block;
	sig_scheme_ptr scheme = self->scheme;
	int i; int n = scheme->n; int l = n - 1;
	element_ptr x_p = get_element(scheme->Z_type, get_part(self->Zx_type, response, 0));
	data_ptr x_message = get_part(self->Zx_type, response, 1);
	element_ptr Vq = get_element(scheme->T_type, get_part(self->claim_public_type, claim_public, 0));
	data_ptr blinded_sig = get_part(self->claim_public_type, claim_public, 1);
	data_ptr Gx = get_part(self->claim_public_type, claim_public, 2);
	element_ptr R_Vs = get_element(scheme->T_type, get_part(self->Gx_type, Gx, 0));
	element_ptr R_Vq = get_element(scheme->T_type, get_part(self->Gx_type, Gx, 1));
	data_ptr R_message = get_part(self->Gx_type, Gx, 2);
	
	int result = 1;
	element_t left_G; element_init(left_G, proof->G_type->field);
	element_t right_G; element_init(right_G, proof->G_type->field);
	element_t left_T; element_init(left_T, scheme->T_type->field);
	element_t right_T; element_init(right_T, scheme->T_type->field);
	
	for (i = 0; i < n; i++) {
		element_ptr x = get_element(proof->Z_type, get_item(self->message_type, x_message, i));
		element_ptr o_x = get_element(proof->Z_type, get_item(self->message_type, x_message, n + i));
		element_ptr R = get_element(proof->G_type, get_item(self->message_commitment_type, R_message, i));
		
		// Verify g ^ x * h ^ o_x = C_m_# ^ e * R_#
		element_pow2_zn(left_G, proof->g, x, proof->h, o_x);
		element_pow_zn(right_G, inst->secret_commitments[self->indices[i]], challenge);
		element_mul(right_G, right_G, R);
		if (element_cmp(left_G, right_G)) {
			result = 0;
			goto end;
		}
	}
	
	// Verify Vq ^ x_p = Vs ^ e * R_Vs
	element_ptr a = get_element(scheme->G_type, get_item(scheme->sig_type, blinded_sig, 0));
	element_ptr b = get_element(scheme->G_type, get_item(scheme->sig_type, blinded_sig, 1));
	element_ptr c = get_element(scheme->G_type, get_item(scheme->sig_type, blinded_sig, 2));
	element_pow_zn(left_T, Vq, x_p);
	pairing_apply(right_T, scheme->g, c, scheme->pairing);
	element_pow_zn(right_T, right_T, challenge);
	element_mul(right_T, right_T, R_Vs);
	if (element_cmp(left_T, right_T)) {
		result = 0;
		goto end;
	}
	
	// Verify <Z_#, a> = <g, A_#>
	for (i = 0; i < l; i++) {
		element_ptr Z = get_element(scheme->G_type, get_item(scheme->public_key_type, self->public_key, 2 + i));
		element_ptr A = get_element(scheme->G_type, get_item(scheme->sig_type, blinded_sig, 3 + i));
		pairing_apply(left_T, Z, a, scheme->pairing);
		pairing_apply(right_T, scheme->g, A, scheme->pairing);
		if (element_cmp(left_T, right_T)) {
			result = 0;
			goto end;
		}
	}
	
	// <Y, a> = <g, b>
	element_ptr Y = get_element(scheme->G_type, get_item(scheme->public_key_type, self->public_key, 1));
	pairing_apply(left_T, Y, a, scheme->pairing);
	pairing_apply(right_T, scheme->g, b, scheme->pairing);
	if (element_cmp(left_T, right_T)) {
		result = 0;
		goto end;
	}
	
	// <Y, A_#> = <g, B_#>
	for (i = 0; i < l; i++) {
		element_ptr A = get_element(scheme->G_type, get_item(scheme->sig_type, blinded_sig, 3 + i));
		element_ptr B = get_element(scheme->G_type, get_item(scheme->sig_type, blinded_sig, 3 + (n - 1) + i));
		pairing_apply(left_T, Y, A, scheme->pairing);
		pairing_apply(right_T, scheme->g, B, scheme->pairing);
		if (element_cmp(left_T, right_T)) {
			result = 0;
			goto end;
		}
	}
	
	// Verify Vx ^ e * Vxy ^ x_0 * Vxy_1 ^ x_1 * Vxy_2 ^ x_2 * ... = Vq ^ e * R_Vq
	element_ptr X = get_element(scheme->G_type, get_item(scheme->public_key_type, self->public_key, 0));
	element_ptr x_0 = get_element(proof->Z_type, get_item(self->message_type, x_message, 0));
	
	pairing_pp_t pp; pairing_pp_init(pp, X, scheme->pairing);
	element_t temp; element_init(temp, scheme->T_type->field);
	pairing_pp_apply(left_T, a, pp);
	element_pow_zn(left_T, left_T, challenge);
	pairing_pp_apply(temp, b, pp);
	element_pow_zn(temp, temp, x_0);
	element_mul(left_T, left_T, temp);
	
	for (i = 0; i < l; i++) {
		element_ptr B = get_element(scheme->G_type, get_item(scheme->sig_type, blinded_sig, 3 + (n - 1) + i));
		element_ptr x = get_element(proof->Z_type, get_item(self->message_type, x_message, 1 + i));
		
		pairing_pp_apply(temp, B, pp);
		element_pow_zn(temp, temp, x);
		element_mul(left_T, left_T, temp);
	}
	pairing_pp_clear(pp);
	element_clear(temp);
	
	element_pow_zn(right_T, Vq, challenge);
	element_mul(right_T, right_T, R_Vq);
	if (element_cmp(left_T, right_T)) {
		result = 0;
		goto end;
	}
	
end:
	element_clear(left_G);
	element_clear(right_G);
	element_clear(left_T);
	element_clear(right_T);
	return result;
}

void require_sig(proof_t proof, sig_scheme_ptr scheme, data_ptr public_key, supplement_t* sig, /* var_t a, var_t b, */ ...) {
	int i;
	block_sig_ptr self = block_sig_base(proof, scheme, public_key);
	*sig = self->sig;
	va_list argp;
	va_start(argp, sig);
	for (i = 0; i < scheme->n; i++) {
		self->indices[i] = var_secret_index(proof, va_arg(argp, var_t));
	}
	va_end(argp);
}

void require_sig_many(proof_t proof, sig_scheme_ptr scheme, data_ptr public_key, supplement_t* sig, var_t* vars) {
	int i;
	block_sig_ptr self = block_sig_base(proof, scheme, public_key);
	*sig = self->sig;
	for (i = 0; i < scheme->n; i++) {
		self->indices[i] = var_secret_index(proof, vars[i]);
	}
}
