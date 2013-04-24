#include <stdint.h>
#include "zkp.h"
#include "zkp_io.h"

void* alloca(size_t);
size_t element_write(field_ptr field, element_t element, FILE* stream) {
	uint32_t size = element_length_in_bytes(element);
	unsigned char *data = (unsigned char*)alloca(4 + size);
	data[0] = size >> 24;
	data[1] = size >> 16;
	data[2] = size >> 8;
	data[3] = size >> 0;
	element_to_bytes(data + 4, element);
	return fwrite(data, 1, 4 + size, stream);
}

size_t element_read(field_ptr field, element_t element, FILE* stream) {
	unsigned char size_data[4];
	size_t len = fread(size_data, 1, 4, stream);
	uint32_t size = (size_data[0] << 24) | (size_data[1] << 16) | (size_data[2] << 8) | (size_data[3] << 0);
	unsigned char *data = (unsigned char*)alloca(size);
	len += fread(data, 1, size, stream);
	element_from_bytes(element, data);
	return len;
}


void _element_init(type_ptr, data_ptr);
void _element_clear(type_ptr, data_ptr);
void _element_write(type_ptr, data_ptr, FILE*);
void _element_read(type_ptr, data_ptr, FILE*);
void element_type_init(element_type_t type, field_ptr field) {
	type->base->init = &_element_init;
	type->base->clear = &_element_clear;
	type->base->write = &_element_write;
	type->base->read = &_element_read;
	type->base->size = sizeof(element_t);
	type->field = field;
}

void _element_init(type_ptr type, data_ptr data) {
	element_init((element_ptr)data, ((element_type_ptr)type)->field);
}

void _element_clear(type_ptr type, data_ptr data) {
	element_clear((element_ptr)data);
}

void _element_write(type_ptr type, data_ptr data, FILE* stream) {
	element_write(((element_type_ptr)type)->field, (element_ptr)data, stream);
}

void _element_read(type_ptr type, data_ptr data, FILE* stream) {
	element_read(((element_type_ptr)type)->field, (element_ptr)data, stream);
}


void _array_init(type_ptr, data_ptr);
void _array_clear(type_ptr, data_ptr);
void _array_write(type_ptr, data_ptr, FILE*);
void _array_read(type_ptr, data_ptr, FILE*);
void array_type_init(array_type_t type, type_ptr item_type, int count) {
	type->base->init = &_array_init;
	type->base->clear = &_array_clear;
	type->base->write = &_array_write;
	type->base->read = &_array_read;
	type->base->size = count * item_type->size;
	type->item_type = item_type;
	type->count = count;
}

void _array_init(type_ptr type, data_ptr data) {
	int i; int count = ((array_type_ptr)type)->count;
	type_ptr item_type = ((array_type_ptr)type)->item_type;
	for (i = 0; i < count; i++) init(item_type, (data_ptr)((char*)data + i * item_type->size));
}

void _array_clear(type_ptr type, data_ptr data) {
	int i; int count = ((array_type_ptr)type)->count;
	type_ptr item_type = ((array_type_ptr)type)->item_type;
	for (i = 0; i < count; i++) clear(item_type, (data_ptr)((char*)data + i * item_type->size));
}

void _array_write(type_ptr type, data_ptr data, FILE* stream) {
	int i; int count = ((array_type_ptr)type)->count;
	type_ptr item_type = ((array_type_ptr)type)->item_type;
	for (i = 0; i < count; i++) write(item_type, (data_ptr)((char*)data + i * item_type->size), stream);
}

void _array_read(type_ptr type, data_ptr data, FILE* stream) {
	int i; int count = ((array_type_ptr)type)->count;
	type_ptr item_type = ((array_type_ptr)type)->item_type;
	for (i = 0; i < count; i++) read(item_type, (data_ptr)((char*)data + i * item_type->size), stream);
}
