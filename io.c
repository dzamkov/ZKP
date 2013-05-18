#include <stdint.h>
#include <pbc.h>
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

void _void_init(type_ptr type, data_ptr data) { }
void _void_clear(type_ptr type, data_ptr data) { }
void _void_copy(type_ptr type, data_ptr dest, data_ptr src) { }
void _void_write(type_ptr type, data_ptr data, FILE* stream) { }
void _void_read(type_ptr type, data_ptr data, FILE* stream) { }
type_t void_type = {{
	&_void_init,
	&_void_clear,
	&_void_copy,
	&_void_write,
	&_void_read,
	0
}};
	
void _element_init(type_ptr, data_ptr);
void _element_clear(type_ptr, data_ptr);
void _element_copy(type_ptr, data_ptr, data_ptr);
void _element_write(type_ptr, data_ptr, FILE*);
void _element_read(type_ptr, data_ptr, FILE*);
void element_type_init(element_type_t type, field_ptr field) {
	type->base->init = &_element_init;
	type->base->clear = &_element_clear;
	type->base->copy = &_element_copy;
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

void _element_copy(type_ptr type, data_ptr dest, data_ptr src) {
	element_set((element_ptr)dest, (element_ptr)src);
}

void _element_write(type_ptr type, data_ptr data, FILE* stream) {
	element_write(((element_type_ptr)type)->field, (element_ptr)data, stream);
}

void _element_read(type_ptr type, data_ptr data, FILE* stream) {
	element_read(((element_type_ptr)type)->field, (element_ptr)data, stream);
}


void _array_init(type_ptr, data_ptr);
void _array_clear(type_ptr, data_ptr);
void _array_copy(type_ptr, data_ptr, data_ptr);
void _array_write(type_ptr, data_ptr, FILE*);
void _array_read(type_ptr, data_ptr, FILE*);
void array_type_init(array_type_t type, type_ptr item_type, int count) {
	type->base->init = &_array_init;
	type->base->clear = &_array_clear;
	type->base->copy = &_array_copy;
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

void _array_copy(type_ptr type, data_ptr dest, data_ptr src) {
	int i; int count = ((array_type_ptr)type)->count;
	type_ptr item_type = ((array_type_ptr)type)->item_type;
	for (i = 0; i < count; i++) {
		size_t offset = i * item_type->size;
		copy(item_type, (data_ptr)((char*)dest + offset), (data_ptr)((char*)src + offset));
	}
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


void _composite_init(type_ptr, data_ptr);
void _composite_clear(type_ptr, data_ptr);
void _composite_copy(type_ptr, data_ptr, data_ptr);
void _composite_write(type_ptr, data_ptr, FILE*);
void _composite_read(type_ptr, data_ptr, FILE*);
void composite_type_init_base(composite_type_t type, int count) {
	type->base->init = &_composite_init;
	type->base->clear = &_composite_clear;
	type->base->copy = &_composite_copy;
	type->base->write = &_composite_write;
	type->base->read = &_composite_read;
	type->part_types = (type_ptr*)pbc_malloc(sizeof(type_ptr) * count);
	type->part_offsets = (size_t*)pbc_malloc(sizeof(size_t) * count);
	type->count = count;
}

void composite_type_init(composite_type_t type, int count, /* type_ptr a, type_ptr b, */ ...) {
	int i;
	composite_type_init_base(type, count);
	va_list argp;
	va_start(argp, count);
	size_t offset = 0;
	for (i = 0; i < count; i++) {
		type->part_types[i] = va_arg(argp, type_ptr);
		type->part_offsets[i] = offset;
		offset += type->part_types[i]->size;
	}
	type->base->size = offset;
	va_end(argp);
}

void composite_type_init_many(composite_type_t type, int count, type_ptr* parts) {
	int i;
	composite_type_init_base(type, count);
	size_t offset = 0;
	for (i = 0; i < count; i++) {
		type->part_types[i] = parts[i];
		type->part_offsets[i] = offset;
		offset += parts[i]->size;
	}
	type->base->size = offset;
}

void composite_type_clear(composite_type_t type) {
	pbc_free(type->part_types);
	pbc_free(type->part_offsets);
}

void _composite_init(type_ptr type, data_ptr data) {
	composite_type_ptr self = ((composite_type_ptr)type);
	int i; int count = self->count;
	for (i = 0; i < count; i++) init(self->part_types[i], (data_ptr)((char*)data + self->part_offsets[i]));
}

void _composite_clear(type_ptr type, data_ptr data) {
	composite_type_ptr self = ((composite_type_ptr)type);
	int i; int count = self->count;
	for (i = 0; i < count; i++) clear(self->part_types[i], (data_ptr)((char*)data + self->part_offsets[i]));
}

void _composite_copy(type_ptr type, data_ptr dest, data_ptr src) {
	composite_type_ptr self = ((composite_type_ptr)type);
	int i; int count = self->count;
	for (i = 0; i < count; i++) {
		size_t offset = self->part_offsets[i];
		copy(self->part_types[i], (data_ptr)((char*)dest + offset), (data_ptr)((char*)src + offset));
	}
}

void _composite_write(type_ptr type, data_ptr data, FILE* stream) {
	composite_type_ptr self = ((composite_type_ptr)type);
	int i; int count = self->count;
	for (i = 0; i < count; i++) write(self->part_types[i], (data_ptr)((char*)data + self->part_offsets[i]), stream);
}

void _composite_read(type_ptr type, data_ptr data, FILE* stream) {
	composite_type_ptr self = ((composite_type_ptr)type);
	int i; int count = self->count;
	for (i = 0; i < count; i++) read(self->part_types[i], (data_ptr)((char*)data + self->part_offsets[i]), stream);
}



