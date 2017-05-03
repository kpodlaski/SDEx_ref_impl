#include "stdafx.h"
#include "ChainHash.h"
#include "stdafx.h"
#include "Hash.h"
#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
const unsigned int SHA256_h_0[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

ChainHash::ChainHash(Hash * _hash) : hash(_hash), DIGEST_SIZE(_hash->DIGEST_SIZE), 
	CHAIN_BLOCK_SIZE(2*_hash->DIGEST_SIZE), 
	_last_hash(new uint32[_hash->IV_SIZE]), _next_init_vector(new uint32[_hash->IV_SIZE]),
	_iteration_count(0){
	_hash->init();
	memcpy(_next_init_vector, _hash->init_vector(),sizeof(uint32)*_hash->IV_SIZE);
}

ChainHash::~ChainHash() {
	delete hash;
	delete[] _last_hash;
	delete[] _next_init_vector;
}

std::string ChainHash::hashNextBlock(std::string input)
{
	return  hashNextBlock((unsigned char*)input.c_str(), input.length());
}

std::string ChainHash::hashNextBlock(unsigned char * input, int length)
{
	if (length == -1) length = CHAIN_BLOCK_SIZE;
	unsigned char * digest = new unsigned char[hash->DIGEST_SIZE];
	memset(digest, 0, sizeof(unsigned char)*hash->DIGEST_SIZE);
	hash->init(_next_init_vector, hash->IV_SIZE); //8 - for sha
	hash->update(input, length);
	std::cout << input << std::endl << length << std::endl;
	//Copy last digest into last_hash
	memcpy(_last_hash, hash->init_vector(), sizeof(unsigned int)*hash->IV_SIZE);
	std::cout << "Check__" << std::endl;
	std::stringstream ivs;
	for (int i = 0; i < 8; i++) {
		ivs << std::setfill('0') << std::setw(8) << std::hex << _last_hash[i] << " ";
	}
	std::cout << ivs.str() << std::endl << "__" << std::endl;
	if (length < CHAIN_BLOCK_SIZE) {
		hash->final(digest);
		memcpy(_last_hash, digest, sizeof(unsigned int)*hash->IV_SIZE);
	}
	updateInitVector();
	_iteration_count += 1;
	std::stringstream ss;

	for (int i = 0; i < hash->DIGEST_SIZE; i++)
		ss << std::setfill('0') << std::setw(2) << std::hex << (int)digest[i];
	delete[] digest;
	return  ss.str();
}

std::string ChainHash::hashNextBlock(std::string inputA, std::string inputB)
{
	return hashNextBlock(inputA + inputB);
}

void ChainHash::clear() {
	hash->init();
	_iteration_count=0;
}

unsigned int * ChainHash::init_vector() {
	return _next_init_vector;
}

unsigned int * ChainHash::last_hash() {
	return _last_hash;
}