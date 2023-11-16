#pragma once
/*
Multiple calculations in AES/Rijndael make use of the Galois field GF(2^8).
In this field, all numbers can be viewed as 7th degree polynomials with 0 or 1 as coefficients
Addition is done with bitwise XORs, and multiplication is done as polynomial multiplication mod x^8+x^4+x^3+x+1 (0x11b)
*/

inline unsigned char rijn_add(unsigned char a, unsigned char b) {
	return a ^ b;
}

// 2 * a
unsigned char rijn_double(unsigned char a) {
	// multiply a by x, saving off x^7 term
	bool carry = (a >> 7) % 1;
	a <<= 1;

	// if x^7 was 1, add irreducable polynomial (without x^8 term)
	if (carry) a ^= 0x1b;
	return a;
}

unsigned char rijn_triple(unsigned char a) {
	return rijn_add(rijn_double(a), a);
	//return rijn_mul(a, 3);
}

// uses the modified peasant's algorithm described at https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
unsigned char rijn_mul(unsigned char a, unsigned char b) {
	unsigned char p = 0; // stores product of a and b
	for (int i = 0; i < 8; ++i) {
		// end if a or b are 0
		if (a == 0 || b == 0) break;

		// if b's x^0 is 1, add a to p
		if (b % 2) p ^= a;

		// divide b by x, discard x^0 term
		b >>= 1;

		a = rijn_double(a);
	}
	return p;
}

// multiply polynomial formed from column by 3x^3+x^2+x+2 (modulo x^4+1)
unsigned char* mix_column(unsigned char c0, unsigned char c1, unsigned char c2, unsigned char c3) {
	unsigned char r[4] = {0, 0, 0, 0};

	r[0] = rijn_double(c0) ^ c3 ^ c2 ^ rijn_triple(c1);
	r[1] = rijn_double(c1) ^ c0 ^ c3 ^ rijn_triple(c2);
	r[2] = rijn_double(c2) ^ c1 ^ c0 ^ rijn_triple(c3);
	r[3] = rijn_double(c3) ^ c2 ^ c1 ^ rijn_triple(c0);

	return r;
}

void mix_columns(unsigned char** state) {
	for (int j = 0; j < 3; ++j) {
		// mix jth column
		unsigned char* mixed = mix_column(state[0][j], state[1][j], state[2][j], state[3][j]);
		for (int i = 0; i < 4; ++i) {
			state[i][j] = mixed[i];
		}
	}
}

// multiply polynomial formed from column by 3x^3+x^2+x+2 (modulo x^4+1)
unsigned char* inv_mix_column(unsigned char c0, unsigned char c1, unsigned char c2, unsigned char c3) {
	unsigned char r[4] = { 0, 0, 0, 0 };

	r[0] = rijn_mul(c0, 14) ^ rijn_mul(c1, 11) ^ rijn_mul(c2, 13) ^ rijn_mul(c3, 9);
	r[1] = rijn_mul(c0, 9) ^ rijn_mul(c1, 14) ^ rijn_mul(c2, 11) ^ rijn_mul(c3, 13);
	r[2] = rijn_mul(c0, 13) ^ rijn_mul(c1, 9) ^ rijn_mul(c2, 14) ^ rijn_mul(c3, 11);
	r[3] = rijn_mul(c0, 11) ^ rijn_mul(c1, 13) ^ rijn_mul(c2, 9) ^ rijn_mul(c3, 14);

	return r;
}

void inv_mix_columns(unsigned char** state) {
	for (int j = 0; j < 3; ++j) {
		// mix jth column
		unsigned char* mixed = inv_mix_column(state[0][j], state[1][j], state[2][j], state[3][j]);
		for (int i = 0; i < 4; ++i) {
			state[i][j] = mixed[i];
		}
	}
}