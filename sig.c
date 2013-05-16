#include <pbc.h>
#include "zkp_io.h"
#include "zkp_sig.h"

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
	
	// Verify e(a, Y) = e(g, b)
	int result = 1;
	pairing_apply(left, a, Y, scheme->pairing);
	pairing_apply(right, scheme->g, b, scheme->pairing);
	if (element_cmp(left, right)) {
		result = 0;
		goto end;
	}
	
	for (i = 0; i < l; i++) {
		element_ptr Z = get_element(scheme->G_type, get_item(scheme->public_key_type, public_key, 2 + i));
		element_ptr A = get_element(scheme->G_type, get_item(scheme->sig_type, sig, 3 + i));
		element_ptr B = get_element(scheme->G_type, get_item(scheme->sig_type, sig, 3 + (n - 1) + i));
		
		// Verify e(a, Z) = e(g, A)
		pairing_apply(left, a, Z, scheme->pairing);
		pairing_apply(right, scheme->g, A, scheme->pairing);
		if (element_cmp(left, right)) {
			result = 0;
			goto end;
		}
		
		// Verify e(A, Y) = e(g, B)
		pairing_apply(left, A, Y, scheme->pairing);
		pairing_apply(right, scheme->g, B, scheme->pairing);
		if (element_cmp(left, right)) {
			result = 0;
			goto end;
		}
	}
	
	// Verify e(X, a) * e(X, b) ^ m_0 * e(X, B_0) ^ m_1 * e(X, B_1) ^ m_2 * ... = e(g, c)
	pairing_pp_t p; pairing_pp_init(p, X, scheme->pairing);
	pairing_pp_apply(left, a, p);
	pairing_pp_apply(temp, b, p);
	element_pow_zn(temp, temp, message[0]);
	element_mul(left, left, temp);
	for (i = 0; i < l; i++) {
		element_ptr B = get_element(scheme->G_type, get_item(scheme->sig_type, sig, 3 + (n - 1) + i));
		pairing_pp_apply(temp, B, p);
		element_pow_zn(temp, temp, message[1 + i]);
		element_mul(left, left, temp);
	}
	pairing_pp_clear(p);
	pairing_apply(right, scheme->g, c, scheme->pairing);
	result = !element_cmp(left, right);
	
end:
	element_clear(left);
	element_clear(right);
	element_clear(temp);
	return result;
}
