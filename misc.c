#include <stdint.h>
#include "zkp.h"
#include "zkp_internal.h"

void* alloca(size_t);
size_t element_out_raw(FILE* stream, element_t element) {
	uint32_t size = element_length_in_bytes(element);
	unsigned char *data = (unsigned char*)alloca(4 + size);
	data[0] = size >> 24;
	data[1] = size >> 16;
	data[2] = size >> 8;
	data[3] = size >> 0;
	element_to_bytes(data + 4, element);
	return fwrite(data, 1, 4 + size, stream);
}

size_t element_inp_raw(element_t element, FILE* stream) {
	unsigned char size_data[4];
	size_t len = fread(size_data, 1, 4, stream);
	uint32_t size = (size_data[0] << 24) | (size_data[1] << 16) | (size_data[2] << 8) | (size_data[3] << 0);
	unsigned char *data = (unsigned char*)alloca(size);
	len += fread(data, 1, size, stream);
	element_from_bytes(element, data);
	return len;
}
