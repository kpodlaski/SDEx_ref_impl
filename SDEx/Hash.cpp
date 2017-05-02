#include "stdafx.h"
#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include "Hash.h"


Hash::Hash(unsigned int _digest_size) : DIGEST_SIZE(_digest_size) {}

std::string Hash::digest_to_string(unsigned char *digest) {
	std::stringstream ss;
	char * buf = new char[2 * DIGEST_SIZE + 4];
	buf[2 * DIGEST_SIZE] = 0;
	for (int i = 0; i < DIGEST_SIZE; i++)
		ss << std::setfill('0') << std::setw(2) << std::hex << (int)digest[i];
	return  ss.str();
}