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

	unsigned int ho[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
	unsigned int oh[8] = { 0x67e6096a,0x85ae67bb,0x72f36e3c,0x3af54fa5,0x7f520e51,0x8c68059b,0xabd9831f,0x19cde05b};
	divide_input_into_subblocks(inputBlock,size);
	unsigned int * init_vector = chainHash->init_vector();
	int block_count = chainHash->CHAIN_BLOCK_SIZE / 2;
	
	unsigned char * h = (unsigned char *) H_IV;
	unsigned char * h_u = (unsigned char *)H_U;
	unsigned char * iv = (unsigned char *)ho;// oh;
	unsigned char * ob = (unsigned char *) outputBlock;
	unsigned int * iO = (unsigned int*) inputOdd;
	/*std::cout <<"MS:"<< size<<" BS:"<<block_count << std::endl;
	for (int i = 0; i< block_count; i++)
		std::cout << std::setfill('0') << std::setw(4) << std::hex << ho[i];
	std::cout << std::endl;
	*/
	for (int i = 0; i < block_count; i++) {
		ob[i] = inputOdd[i] ^ h[i] ^ iv[ (i/4+1)*4-i%4-1 ];
		/*std::cout << " M:" << std::setfill('0') << std::setw(2) << std::hex << (int) inputOdd[i];
		std::cout << " 4:" << std::setfill('0') << std::setw(2) << std::hex << (int) h[i];
		std::cout << " H:" << std::setfill('0') << std::setw(2) << std::hex << (int) iv[i] << std::endl;
		std::cout << std::dec<<i+1 << std::endl;
		*/
		ob[block_count + i] = inputEven[i] ^ h[i] ^ h_u[i];
	}
	

	/*for (int i = 0; i < block_count/sizeof(int); i++) {
		ob[i] = iO[i] ^ H_IV[i] ^ oh[i];
		std::cout << " M:" << std::setfill('0') << std::setw(2) << std::hex << (int)inputOdd[i];
		std::cout << " 4:" << std::setfill('0') << std::setw(2) << std::hex << (int)h[i];
		std::cout << " H:" << std::setfill('0') << std::setw(2) << std::hex << (int)iv[i] << std::endl;
		std::cout << std::dec << i + 1 << std::endl;
		ob[block_count + i] = inputEven[i] ^ H_IV[i] ^ H_U[i];
	}*/

	/*unsigned char * c;
	c = (unsigned char *)iO;
	std::cout << "M:" << std::setfill('0') << std::setw(8) << std::hex << * ((unsigned int*)c) << std::endl;
	for (int i = 0; i < 4; i++)
	{
		std::cout << "M:" << *(c+i) << "\t\t" << std::bitset<8>(*(c+i)) << "\t" << std::setfill('0') << std::setw(2) << std::hex << (int)*(c+i) << std::endl;
		//std::cout << (char)iO[0] << "\t\t" << std::bitset<8>((char)iO[0]) << std::endl;
		//std::cout << iO[0] << "\t" << std::bitset<32>(iO[0]) << std::endl;
	}
	c = (unsigned char *)H_IV;
	std::cout << "4:" << std::setfill('0') << std::setw(8) << std::hex << *((unsigned int*)c) << std::endl;
	for (int i = 0; i < 4; i++)
	{
		std::cout << "4:" << *(c+i) << "\t\t" << std::bitset<8>(*(c+i)) << "\t" << std::setfill('0') << std::setw(2) << std::hex << (int)*(c+i) << std::endl;
		//std::cout << (char)H_IV[0] << "\t\t" << std::bitset<8>((char)H_IV[0]) << std::endl;
		//std::cout << H_IV[0] << "\t" << std::bitset<32>(H_IV[0]) << std::endl;
	}
	c = (unsigned char *)init_vector;
	std::cout << "H:" << std::setfill('0') << std::setw(8) << std::hex << *((unsigned int*)c) << std::endl;
	for (int i = 0; i < 4; i++)
	{
		std::cout << "H:" << *(c+i) << "\t\t" << std::bitset<8>(*(c+i)) << "\t" << std::setfill('0') << std::setw(2) << std::hex << (int)*(c+i) << std::endl;
		//std::cout << init_vector[0] << "\t" << std::bitset<32>(init_vector[0]) << std::endl;
		//std::cout << std::endl;
	}
	for (int i = 0; i < 4; i++)
	{
		c = (unsigned char *)outputBlock;
		std::cout << "S:" << *(c+i) << "\t\t" << std::bitset<8>(*(c+i)) << "\t" << std::setfill('0') << std::setw(2) << std::hex << (int)*(c+i) << std::endl;
		//std::cout << outputBlock[0] << "\t" << std::bitset<32>(outputBlock[0]) << std::endl;
	}


	/*for (int i = 0; i < block_count; i++)
		std::cout << std::bitset<8>(inputOdd[i]);
	std::cout << std::endl;
	
	for (int i = 0; i < block_count/sizeof(int); i++)
		std::cout << std::bitset<32>(iO[i]); 
		std::cout << "s"<<std::endl;
	;

	for (int i = 0; i < block_count / 2; i++)
		std::cout << std::setfill('0') << std::setw(2) << std::hex << H_IV[i];
	std::cout << std::endl;
	for (int i = 0; i < block_count / 2; i++)
		std::cout << init_vector[i];
	*/
	std::string cs = chainHash->hashNextBlock((unsigned char *)inputBlock);
	//std::cout << cs << std::endl;
	unsigned char * iv2 = (unsigned char *)chainHash->init_vector();
	unsigned char * lh2 = (unsigned char *)chainHash->last_hash();
	/*std::cout << "BLOCK: 0" << std::endl;
	std::stringstream ivs, hs;
	for (int i = 0; i < 8; i++) {
		ivs << std::setfill('0') << std::setw(8) << std::hex << chainHash->init_vector()[i] << " ";
		hs << std::setfill('0') << std::setw(8) << std::hex << chainHash->last_hash()[i] << " ";
	}
	std::cout << "IV:\t" << ivs.str() << std::endl;
	std::cout << "hash:\t" << hs.str() << std::endl;
	std::cout << "------------------------------------------" << std::endl;
	/*std::cout << "h1+h0:\t";
	for (int i = 0; i< block_count; i++)
		std::cout << std::setfill('0') << std::setw(2) << std::hex << (int) iv2[i];
	std::cout << std::endl << "h1:\t";
	for (int i = 0; i< block_count; i++)
		std::cout <<std::setfill('0') << std::setw(2) << std::hex << (int) lh2[i];
	std::cout << std::endl;
	*/
}

void SDExCryptAlg::block_cypher(const char * inputBlock, unsigned int size, unsigned int * outputBlock) {
	divide_input_into_subblocks(inputBlock,size); 
	unsigned char * init_vector = (unsigned char *) chainHash->init_vector();
	unsigned char * last_hash = (unsigned char *) chainHash->last_hash();
	int block_count = chainHash->CHAIN_BLOCK_SIZE / 2;
	unsigned char * h_u = (unsigned char *) H_U;
	unsigned char * ob = (unsigned char *) outputBlock;
	unsigned int * iO = (unsigned int*) inputOdd;


	for (int i = 0; i < block_count; i++) {
		ob[i] = inputOdd[i] ^ init_vector[(i / 4 + 1) * 4 - i % 4 - 1];
		ob[block_count + i] = inputEven[i]^ last_hash[(i / 4 + 1) * 4 - i % 4 - 1] ^ h_u[i];
	}
	chainHash->hashNextBlock((unsigned char *)inputBlock);
	/*if (block_crypted < 5) {
		std::stringstream ivs, hs;
		std::cout << "------------------------------------------" << std::endl;
		std::cout << "BLOCK: " << std::dec << block_crypted << std::endl;
		for (int i = 0; i < 8; i++) {
			ivs << std::setfill('0') << std::setw(8) << std::hex << chainHash->init_vector()[i] << " ";
			hs << std::setfill('0') << std::setw(8) << std::hex << chainHash->last_hash()[i] << " ";
		}
		std::cout << "IV:\t" << ivs.str() << std::endl;
		std::cout << "hash:\t" << hs.str() << std::endl;
		std::cout << "------------------------------------------" << std::endl;
	}
	*/
}

void SDExCryptAlg::first_block_decypher(const char * inputBlock, unsigned int size, unsigned int * outputBlock) {

	divide_input_into_subblocks(inputBlock, size);
	unsigned int * init_vector = chainHash->init_vector();
	int block_count = chainHash->CHAIN_BLOCK_SIZE / 2;
	unsigned char * h = (unsigned char *)H_IV;
	unsigned char * h_u = (unsigned char *)H_U;
	unsigned char * iv = (unsigned char *) init_vector;// oh;
	unsigned char * ob = (unsigned char *)outputBlock;
	unsigned int * iO = (unsigned int*)inputOdd;
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
			/*std::cout <<"{{}}}"<< outputBlock2<<"{{}}}"<<std::endl;
			for (int i = 0; i < chainHash->CHAIN_BLOCK_SIZE; i++)
				std::cout << "{{}}}" << outputBlock[i];
			std::cout << std::endl;
			*/
		}
		else {
			block_cypher(message.substr(block_crypted * chainHash->CHAIN_BLOCK_SIZE, size).c_str(),
				size, (unsigned int *)outputBlock);
		}
		block_crypted++;
		fwrite(outputBlock, sizeof(char), chainHash->CHAIN_BLOCK_SIZE, outFile);
		std::string outputBlock2((char *)outputBlock, chainHash->CHAIN_BLOCK_SIZE);
		ss << outputBlock2;
//		for (int i = 0; i < chainHash->CHAIN_BLOCK_SIZE; i++) {
			//
//			ss << outputBlock[i];
//		}
		//std::cout << "[[]]" << ss.str() << "[[]]" << std::endl;
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
