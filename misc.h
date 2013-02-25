// Requires:
//  * pbc.h
#ifndef MISC_H_
#define MISC_H_

// Outputs an element to a stream, returning the number of bytes that were
// written, or 0, if an error occured.
size_t element_out_raw(FILE* stream, element_t element);

// Reads an element from a stream, returning the number of bytes that were
// read, or 0, if an error occured.
size_t element_inp_raw(element_t element, FILE* stream);

#endif // MISC_H_
