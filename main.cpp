/*
	Encodes text using AES encryption
	Only uses the S-box and inverse S-box lookup tables
	MixColumns does math using GF(2^8)
	Input text followed by key (<=16 chars)
*/

#include "substitution.h"
#include "field_math.h"
#include "key.h"
#include <iostream>
#include <string>

// cyclically shift each row to the left by its number
void shift_rows(unsigned char** state) {
	// keeps track of the char that's replaced
	unsigned char replaced;

	// row 0 is unchanged

	// row 1 shifts 1 to the left
	replaced = state[1][3];
	for (int j = 2; j >= 0; --j) {
		state[1][j + 1] = state[1][j];
	}
	state[1][0] = replaced;

	// row 2 shifts twice
	for (int j = 0; j < 2; ++j) {
		replaced = state[2][j + 2];
		state[2][j + 2] = state[2][j];
		state[2][j] = replaced;
	}

	// row 3 shifts 1 to the right
	replaced = state[3][0];
	for (int j = 0; j <= 2; ++j) {
		state[3][j] = state[3][j + 1];
	}
	state[3][3] = replaced;
}

// cyclically shift each row to the right by its number
void inv_shift_rows(unsigned char** state) {
	// keeps track of the char that's replaced
	unsigned char replaced;

	// row 0 is unchanged

	// row 1 shifts 1 to the right
	replaced = state[1][0];
	for (int j = 0; j <= 2; ++j) {
		state[1][j] = state[1][j + 1];
	}
	state[1][3] = replaced;

	// row 2 shifts twice
	for (int j = 0; j < 2; ++j) {
		replaced = state[2][j + 2];
		state[2][j + 2] = state[2][j];
		state[2][j] = replaced;
	}

	// row 3 shifts 1 to the left
	replaced = state[3][3];
	for (int j = 2; j >= 0; --j) {
		state[3][j + 1] = state[3][j];
	}
	state[3][0] = replaced;
}

void print_state(unsigned char** state) {
	for (int i = 0; i < 4; ++i) {
		for (int j = 0; j < 4; ++j) {
			std::cout << state[i][j];
		}
	}
}

void encrypt_block(unsigned char** state, key_type type, long* key, bool detailed) {
	if (detailed) {
		std::cout << "Encrypt block:\n";
		print_state(state);
	}

	// generate round keys
	long* round_keys;
	round_keys = key_expansion(type, key);

	// initial round key addition
	add_round_key(round_keys, 0, state);

	// 10/12/14 rounds
	int num_rounds = rounds_from_type(type);
	for (int round = 0; round < num_rounds - 1; ++round) {
		sub_bytes(state);
		shift_rows(state);
		mix_columns(state);
		add_round_key(round_keys, round + 1, state);
	}
	
	// final round
	sub_bytes(state);
	shift_rows(state);
	add_round_key(round_keys, num_rounds + 1, state);

	delete round_keys;
}

void decrypt_block(unsigned char** state, key_type type, long* key, bool detailed) {
	if (detailed) {
		std::cout << "Decrypt block:\n";
		print_state(state);
	}

	// generate round keys
	long* round_keys;
	round_keys = key_expansion(type, key);

	int num_rounds = rounds_from_type(type);

	// final round
	add_round_key(round_keys, num_rounds + 1, state);
	inv_shift_rows(state);
	inv_sub_bytes(state);

	// 10/12/14 rounds
	for (int round = num_rounds - 2; round >= 0 ; --round) {
		add_round_key(round_keys, round + 1, state);
		inv_mix_columns(state);
		inv_shift_rows(state);
		inv_sub_bytes(state);
	}

	// initial round key addition
	add_round_key(round_keys, 0, state);

	delete round_keys;
}


//void encrypt_block(unsigned char** state, key_type type, long* key, bool detailed) {
//	sub_bytes(state);
//}
//
//void decrypt_block(unsigned char** state, key_type type, long* key, bool detailed) {
//	inv_sub_bytes(state);
//}

int main() {
	bool hex_mode = false;
	bool detailed_mode = false;

	std::string text;
	std::string key;
	long* long_key = NULL;

	std::cout << "Enter plaintext: ";
	std::getline(std::cin, text);

	key_type type = key_128;
	
	// get key and key type
	while (true) {
		std::cout << "Enter key: ";
		std::getline(std::cin, key);
		if (hex_mode) {
			for (int i = 0; i < key.size(); ++i) {
				key[i] = tolower(key[i]);
			}
			if (key.size() % 2 != 0) {
				std::cout << "You should have an even number of nibbles. Please re-enter";
				continue;
			}
			if (key.size() > 32) {
				std::cout << "Your key (" << key.size() * 4 << " bits) is longer than 256 bits. Please re-enter.\n";
				continue;
			}
			else if (key.size() > 24) {
				type = key_256;
				if (detailed_mode) {
					std::cout << "The key is " << key.size() * 4 << " bits.\n";
				}
				if (key.size() != 32) {
					if (detailed_mode) std::cout << "It will be padded to 256 bits.\n";
					key += "00";
				}
			}
			else if (key.size() > 16) {
				type = key_192;
				if (detailed_mode) {
					std::cout << "The key is " << key.size() * 4 << " bits.\n";
				}
				if (key.size() != 24) {
					if (detailed_mode) std::cout << "It will be padded to 192 bits.\n";
					key += "00";
				}
			}
			else {
				if (detailed_mode) {
					type = key_128;
					std::cout << "The key is " << key.size() * 4 << " bits.\n";
					if (key.size() != 8) std::cout << "It will be padded to 128 bits.\n";
				}
				if (key.size() != 16) {
					if (detailed_mode) std::cout << "It will be padded to 128 bits.\n";
					while (key.size() < 8) key += "00";
				}
			}
		}
		else {
			if (key.size() > 16) {
				std::cout << "Your key (" << key.size() * 8 << " bits) is longer than 256 bits. Please re-enter.\n";
				continue;
			}
			else if (key.size() > 12) {
				type = key_256;
				if (detailed_mode) {
					std::cout << "The key is " << key.size() * 8 << " bits.\n";
				}
				if (key.size() != 16) {
					if (detailed_mode) std::cout << "It will be padded to 256 bits.\n";
					key += "\0";
				}
			}
			else if (key.size() > 8) {
				type = key_192;
				if (detailed_mode) {
					std::cout << "The key is " << key.size() * 8 << " bits.\n";
				}
				if (key.size() != 12) {
					if (detailed_mode) std::cout << "It will be padded to 192 bits.\n";
					key += "\0";
				}
				else {
					type = key_128;
					if (detailed_mode) {
						std::cout << "The key is " << key.size() * 8 << " bits.\n";
					}
					if (key.size() != 8) {
						if (detailed_mode) std::cout << "It will be padded to 128 bits.\n";
						while (key.size() < 8) key += "\0";
					}
				}
			}
		}
		break;
	}
	
	// convert key to long*
	switch (type) {
	case key_256:
		long_key = new long[8];
		break;
	case key_192:
		long_key = new long[6];
		break;
	case key_128:
		long_key = new long[4];
		break;
	}
	if (hex_mode) {
		long l;
		for (int i = 0; i < key.size() / 4; ++i) {
			l = 0;
			for (int j = 0; j < 8; ++j) {
				l << 4;
				unsigned char c = key[8 * i + j];
				if (c >= 'a') l += c - 'a' + 10;
				else l += c - '0';
			}
			long_key[i] = l;
		}
	}
	else {
		long l;
		for (int i = 0; i < key.size() / 4; ++i) {
			l = 0;
			for (int j = 0; j < 4; ++j) {
				l << 8;
				l += key[4 * i + j];
			}
			long_key[i] = l;
		}
	}

	// encrypt & decrypt block-by-block
	for (int block = 0; block < text.size() / 16; ++block) {
		unsigned char** state = new unsigned char*[4];
		for (int i = 0; i < 4; ++i) {
			state[i] = new unsigned char[4];
			for (int j = 0; j < 4; ++j) {
				state[i][j] = text[block * 16 + i * 4 + j];
			}
		}
		//print_state(state);
		//std::cout << "\n";
		encrypt_block(state, type, long_key, detailed_mode);
		if (detailed_mode) std::cout << "Encrypted block: ";
		print_state(state);
		std::cout << "\n";
		decrypt_block(state, type, long_key, detailed_mode);
		if (detailed_mode) std::cout << "Decrypted block: ";
		print_state(state);
		std::cout << "\n";
	}
}