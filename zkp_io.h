#ifndef ZKP_IO_H_
#define ZKP_IO_H_

// Writes an element to a stream, returning the number of bytes that were
// written, or 0, if an error occured.
size_t element_write(field_ptr field, element_t element, FILE* stream);

// Reads an element from a stream, returning the number of bytes that were
// read, or 0, if an error occured.
size_t element_read(field_ptr field, element_t element, FILE* stream);

// A pointer to arbitrary data with a known type.
typedef void* data_ptr;

// Describes a type of data.
typedef struct type_s *type_ptr;
typedef struct type_s {
	void (*init)(type_ptr, data_ptr);
	void (*clear)(type_ptr, data_ptr);
	void (*copy)(type_ptr, data_ptr, data_ptr);
	void (*write)(type_ptr, data_ptr, FILE*);
	void (*read)(type_ptr, data_ptr, FILE*);
	size_t size;
} type_t[1];

// Initializes data with the given type.
static inline void init(type_ptr type, data_ptr data) {
	type->init(type, data);
}

// Allocates and initializes data with the given type.
static inline data_ptr new(type_ptr type) {
	data_ptr data = (data_ptr)pbc_malloc(type->size);
	type->init(type, data);
	return data;
}

// Clears data of the given type.
static inline void clear(type_ptr type, data_ptr data) {
	type->clear(type, data);
}

// Copies data of a given type.
static inline void copy(type_ptr type, data_ptr dest, data_ptr src) {
	type->copy(type, dest, src);
}

// Clears and deallocates data of the given type.
static inline void delete(type_ptr type, data_ptr data) {
	type->clear(type, data);
	pbc_free(data);
}

// Writes data of the given type to a stream.
static inline void write(type_ptr type, data_ptr data, FILE* stream) {
	type->write(type, data, stream);
}

// Reads data of the given type from a stream.
static inline void read(type_ptr type, data_ptr data, FILE* stream) {
	type->read(type, data, stream);
}

// Describes an element type.
typedef struct element_type_s *element_type_ptr;
typedef struct element_type_s {
	type_t base;
	field_ptr field;
} element_type_t[1];

// Describes an array type.
typedef struct array_type_s *array_type_ptr;
typedef struct array_type_s {
	type_t base;
	int count;
	type_ptr item_type;
} array_type_t[1];

// Describes a composite type.
typedef struct composite_type_s *composite_type_ptr;
typedef struct composite_type_s {
	type_t base;
	int count;
	type_ptr *part_types;
	size_t *part_offsets;
} composite_type_t[1];

// The void type, which has only one possible value.
extern type_t void_type;

// Initializes an element type of the given field.
void element_type_init(element_type_t type, field_ptr field);

// Initializes a fixed-size array type with the given item type and item count.
void array_type_init(array_type_t type, type_ptr item_type, int count);

// Initializes a composite type with the given part types.
void composite_type_init(composite_type_t type, int count, /* type_ptr a, type_ptr b, */ ...);
void composite_type_init_many(composite_type_t type, int count, type_ptr* parts);

// Frees the space occupied by a composite type.
void composite_type_clear(composite_type_t type);

// Gets an element pointer to the element in the given data.
static inline element_ptr get_element(element_type_t type, data_ptr data) {
	return (element_ptr)data;
}

// Gets a data pointer to an item within an array.
static inline data_ptr get_item(array_type_t type, data_ptr data, int index) {
	return (data_ptr)((char*)data + index * type->item_type->size);
}

// Gets a data pointer to a part within a composite.
static inline data_ptr get_part(composite_type_t type, data_ptr data, int index) {
	return (data_ptr)((char*)data + type->part_offsets[index]);
}

#endif // ZKP_IO_H_
