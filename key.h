#pragma once
#include "substitution.h"

// denotes the bit-length of the key
// also determines number of rounds
enum key_type {
	key_128,
	key_192,
	key_256
};

// cyclically left-shift a 4-byte word by a byte
long rot_word(long word) {
	char high = word >> 24;
	return word << 8 + high;
}

// 10 rounds for 128 bits, 12 for 192, and 14 for 256
inline int rounds_from_type(key_type type) {
	return 10 + type * 2;
}

// number of 4-byte words for original key
inline int word_length_from_type(key_type type) {
	return 4 + type * 2;
}

// constant based on round used in key_expansion
long rcon[10] = {
	0x01000000,
	0x02000000,
	0x04000000,
	0x08000000,
	0x10000000,
	0x20000000,
	0x40000000,
	0x80000000,
	0x1b000000,
	0x36000000
};


// expands 128/192/256-bit key to array of words
long* key_expansion(key_type type, long* key) {
	// number of round keys needed
	int r = rounds_from_type(type) + 1;

	// length in words of key
	int n = word_length_from_type(type);

	// array of 4-byte words that hold keys
	long* key_words = new long[4 * r];

	for (int i = 0; i < 4 * r; ++i) {
		if (i < n) {
			key_words[i] = key[i];
		}
		else if (i % n == 0) {
			key_words[i] = key_words[i - n] ^ sub_word(rot_word(key_words[i - n])) ^ rcon[i/n];
		}
		else if (n > 6 && i % n == 4) {
			key_words[i] = key_words[i - n] ^ sub_word(key_words[i - n]);
		}
		else {
			key_words[i] = key_words[i - n] ^ key_words[i - 1];
		}
	}

	return key_words;
}



// xor each byte of state with a byte from the current round key
void add_round_key(long* round_keys, int r, unsigned char** state) {
	for (int i = 0; i < 4; ++i) {
		long key_word = round_keys[r * 4 + i];
		for (int j = 0; j < 4; ++j) {
			state[i][j] ^= word_byte(key_word, j);
		}
	}
}