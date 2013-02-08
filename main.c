#include <pbc.h>
#include <stdio.h>
#include "sig.h"

int main() {
	pairing_t pairing;
	
	FILE* fparam = fopen("a.param", "rb");
	char param[1024];
	size_t count = fread(param, 1, 1024, fparam);
	fclose(fparam);
	if (!count) pbc_die("input error");
	pairing_init_set_buf(pairing, param, count);
	
	
	
	return 0;
}
