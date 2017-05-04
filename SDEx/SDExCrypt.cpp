#include "stdafx.h"
#include "SDExCrypt.h"
#include "Hash.h"
#include <algorithm> 
#include <sstream>
#include <iostream>
#include <iomanip>
#include <bitset>

void SDExCryptAlg::divide_input_into_subblocks(const char * inputBlock, unsigned int input_size) {
	memset(inputEven, 0, chainHash->CHAIN_BLOCK_SIZE / 2);
	memset(inputOdd, 0, chainHash->CHAIN_BLOCK_SIZE / 2);
	memcpy(inputOdd, inputBlock, std::min(input_size, chainHash->CHAIN_BLOCK_SIZE / 2));
	if (input_size > chainHash->CHAIN_BLOCK_SIZE / 2) {
		memcpy(inputEven, inputBlock + (chainHash->CHAIN_BLOCK_SIZE / 2), 
			std::min(input_size-chainHash->CHAIN_BLOCK_SIZE / 2, chainHash->CHAIN_BLOCK_SIZE / 2)
		);
	}
	
}

void SDExCryptAlg::first_block_cypher(const char * inputBlock, unsigned int size, unsigned int * outputBlock) {

	divide_input_into_subblocks(inputBlock,size);
	int block_count = chainHash->CHAIN_BLOCK_SIZE / 2;	
	unsigned char * h = (unsigned char *) H_IV;
	unsigned char * h_u = (unsigned char *)H_U;
	unsigned char * iv = (unsigned char *)chainHash->init_vector();
	unsigned char * ob = (unsigned char *) outputBlock;
	for (int i = 0; i < block_count; i++) {
		ob[i] = inputOdd[i] ^ h[i] ^ iv[ (i/4+1)*4-i%4-1 ];
		ob[block_count + i] = inputEven[i] ^ h[i] ^ h_u[i];
	}
	chainHash->hashNextBlock((unsigned char *)inputBlock);
}


void SDExCryptAlg::block_cypher(const char * inputBlock, unsigned int size, unsigned int * outputBlock) {
	divide_input_into_subblocks(inputBlock,size); 
	unsigned char * init_vector = (unsigned char *) chainHash->init_vector();
	unsigned char * last_hash = (unsigned char *) chainHash->last_hash();
	int block_count = chainHash->CHAIN_BLOCK_SIZE / 2;
	unsigned char * h_u = (unsigned char *) H_U;
	unsigned char * ob = (unsigned char *) outputBlock;
	for (int i = 0; i < block_count; i++) {
		ob[i] = inputOdd[i] ^ init_vector[(i / 4 + 1) * 4 - i % 4 - 1];
		ob[block_count + i] = inputEven[i]^ last_hash[(i / 4 + 1) * 4 - i % 4 - 1] ^ h_u[i];
	}
	chainHash->hashNextBlock((unsigned char *)inputBlock);
}

void SDExCryptAlg::first_block_decypher(const char * inputBlock, unsigned int size, unsigned int * outputBlock) {

	divide_input_into_subblocks(inputBlock, size);
	int block_count = chainHash->CHAIN_BLOCK_SIZE / 2;
	unsigned char * h = (unsigned char *)H_IV;
	unsigned char * h_u = (unsigned char *)H_U;
	unsigned char * iv = (unsigned char *)chainHash->init_vector();
	unsigned char * ob = (unsigned char *)outputBlock;
	for (int i = 0; i < block_count; i++) {
		ob[i] = inputOdd[i] ^ h[i] ^ iv[(i / 4 + 1) * 4 - i % 4 - 1];
		ob[block_count + i] = inputEven[i] ^ h[i] ^ h_u[i];
	}
	chainHash->hashNextBlock((unsigned char *)outputBlock);
}

void SDExCryptAlg::block_decypher(const char * inputBlock, unsigned int size, unsigned int * outputBlock) {
	divide_input_into_subblocks(inputBlock, size);
	unsigned char * init_vector = (unsigned char *)chainHash->init_vector();
	unsigned char * last_hash = (unsigned char *)chainHash->last_hash();
	int block_count = chainHash->CHAIN_BLOCK_SIZE / 2;
	unsigned char * h_u = (unsigned char *)H_U;
	unsigned char * ob = (unsigned char *)outputBlock;
	for (int i = 0; i < block_count; i++) {
		ob[i] = inputOdd[i] ^ init_vector[(i / 4 + 1) * 4 - i % 4 - 1];
		ob[block_count + i] = inputEven[i] ^ last_hash[(i / 4 + 1) * 4 - i % 4 - 1] ^ h_u[i];
	}
	chainHash->hashNextBlock((unsigned char *)outputBlock);
}

std::string SDExCryptAlg::crypt(std::string message) {
	long long int message_len = message.length();
	unsigned char * outputBlock = new unsigned char[chainHash->CHAIN_BLOCK_SIZE];
	std::stringstream ss;
	FILE * outFile;
	//wb in order not to translate end of the line LF into CRLF
	outFile = fopen("encrypted", "wb");
	while (message_len > 0) {
		int size = (int)std::min((long long)chainHash->CHAIN_BLOCK_SIZE, message_len);
		if (block_crypted < 1) {
			first_block_cypher(message.substr(0,size).c_str(), size , (unsigned int *)outputBlock);
			std::string outputBlock2((char *)outputBlock, chainHash->CHAIN_BLOCK_SIZE);
		}
		else {
			block_cypher(message.substr(block_crypted * chainHash->CHAIN_BLOCK_SIZE, size).c_str(),
				size, (unsigned int *)outputBlock);
		}
		block_crypted++;
		fwrite(outputBlock, sizeof(char), chainHash->CHAIN_BLOCK_SIZE, outFile);
		std::string outputBlock2((char *)outputBlock, chainHash->CHAIN_BLOCK_SIZE);
		ss << outputBlock2;
		message_len -= chainHash->CHAIN_BLOCK_SIZE;
	}
	fclose(outFile);
	std::cout << "Block encrypted :" << block_crypted << " Last Block:" << message_len + chainHash->CHAIN_BLOCK_SIZE << std::endl;
	return  ss.str();
}


std::string SDExCryptAlg::decrypt(std::string message) {
	long long int message_len = message.length();
	unsigned char * outputBlock = new unsigned char[chainHash->CHAIN_BLOCK_SIZE];
	std::stringstream ss;
	while (message_len > 0) {
		int size = (int)std::min((long long)chainHash->CHAIN_BLOCK_SIZE, message_len);
		if (block_crypted < 1) {
			first_block_decypher(message.substr(0, size).c_str(), size, (unsigned int *)outputBlock);
		}
		else {
			block_decypher(message.substr(block_crypted * chainHash->CHAIN_BLOCK_SIZE, size).c_str(),
				size, (unsigned int *)outputBlock);
		}
		block_crypted++;
		std::string outputBlock((char *)outputBlock, chainHash->CHAIN_BLOCK_SIZE);
		ss << outputBlock;
		message_len -= chainHash->CHAIN_BLOCK_SIZE;
	}
	std::cout << "Block decrypted :" << block_crypted << " Last Block:" << message_len + chainHash->CHAIN_BLOCK_SIZE << std::endl;
	return ss.str();
}

SDExCryptAlg::SDExCryptAlg(Hash * _hash, std::string IV, std::string U) : 
	chainHash(new DMChainHash(_hash)), block_crypted(0)
{
	H_IV = new unsigned int[_hash->IV_SIZE];
	H_U = new unsigned int[_hash->IV_SIZE];
	inputOdd = new unsigned char[chainHash->CHAIN_BLOCK_SIZE / 2];
	inputEven = new unsigned char[chainHash->CHAIN_BLOCK_SIZE / 2];
	_hash->init();
	_hash->update((unsigned char*)IV.c_str(), IV.length());
	_hash->final((unsigned char*)H_IV);
	_hash->digest_to_string((unsigned char*)H_IV);
	_hash->init();
	_hash->update((unsigned char*)U.c_str(), U.length());
	_hash->final((unsigned char*)H_U);
	_hash->init();
	//For now pure h_0
	return;
	std::string new_h0 = IV + std::string((char *) _hash->init_vector(),_hash->DIGEST_SIZE);
	_hash->update((unsigned char*) U.c_str(), U.length());
	unsigned int * H_0 = new unsigned int[_hash->IV_SIZE];
	_hash->final((unsigned char*)H_0);
	_hash->init(H_0,_hash->IV_SIZE);
}


SDExCryptAlg::~SDExCryptAlg()
{
	delete chainHash;
	delete []  H_IV;
	delete [] H_U;
	delete [] inputOdd;
	delete [] inputEven;
}
