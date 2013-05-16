#ifndef ZKP_SIG_H_
#define ZKP_SIG_H_

// Describes a CL-signature scheme.
typedef struct sig_scheme_s *sig_scheme_ptr;
typedef struct sig_scheme_s {
	
	// The type for a secret key in this signature scheme.
	array_type_t secret_key_type;
	
	// The type for a public key in this signature scheme.
	array_type_t public_key_type;
	
	// The type for a signature in this signature scheme.
	array_type_t sig_type;
	
	// The type for elements used as signable values in this signature scheme.
	element_type_t Z_type;
	
	// The type for group elements used in this signature scheme.
	element_type_t G_type;
	
	// The type for an element produced by the bilinear pairing in this signature scheme.
	element_type_t T_type;
	
	// The number of values signed by each signature.
	int n;
	
	// The pairing for this signature scheme.
	pairing_ptr pairing;
	
	// The generator for this signature scheme.
	element_t g;
	
} sig_scheme_t[1];

// Initializes a signature scheme.
void sig_scheme_init(sig_scheme_t scheme, int n, pairing_ptr pairing, element_t g);

// Frees the space occupied by a signature scheme.
void sig_scheme_clear(sig_scheme_t scheme);

// Creates a random secret/public key pair for a given signature scheme.
void sig_key_setup(sig_scheme_t scheme, data_ptr secret_key, data_ptr public_key);

// Signs a message (a set of elements in Z) using a given signature scheme and secret key.
void sig_sign(sig_scheme_t scheme, data_ptr secret_key, data_ptr sig, element_t message[]);

// Verifies a signed message (a set of elements in Z) using a given signature scheme and public key. Returns
// a non-zero value if the signature is valid.
int sig_verify(sig_scheme_t scheme, data_ptr public_key, data_ptr sig, element_t message[]);

#endif // ZKP_SIG_H_
