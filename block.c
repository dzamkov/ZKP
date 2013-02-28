#include <assert.h>
#include "zkp.h"
#include "zkp_internal.h"

void block_insert(proof_t proof, struct block_s *block) {
	proof->witness_extra_size += block->witness_extra_size;
	if (proof->last_block == NULL) {
		proof->first_block = block;
	} else {
		proof->last_block->next = block;
	}
	proof->last_block = block;
	block->next = NULL;
}

void blocks_clear(proof_t proof) {
	struct block_s* current = proof->first_block;
	while (current != NULL) {
		current->clear(current);
		current = current->next;
	}
}
