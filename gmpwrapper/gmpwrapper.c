#include <gmp.h>

int integer_cube_root(void * bs, size_t count, void ** root_buffer, size_t *root_buffer_length) {
	// Import integer values from byte array
	mpz_t value;
	mpz_init(value);
	int order = -1;
	size_t size = sizeof(bs[0]);
	int endian = 0;
	size_t nails = 0;
	mpz_import(value, count, order, size, endian, nails, bs);

	// Calculate cube root
	mpz_t root;
	mpz_init(root);
	int exact = mpz_root(root, value, 3);

	// Export root value and byte length to provided pointers.
	*root_buffer = mpz_export(NULL, root_buffer_length, order, size, endian, nails, root);

	// Return whether the root is an exact value.
	return exact;
}
