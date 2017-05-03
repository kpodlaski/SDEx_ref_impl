#ifndef CHAIN_HASH_H
#define CHAIN_HASH_H
#include <string>
#include "Hash.h"



class ChainHash
{
protected:
	typedef unsigned int uint32;
	uint32 _iteration_count;
	uint32 * _last_hash;
	uint32 * _next_init_vector;
	Hash *  hash;
	//ChainHash(uint32);
	ChainHash(Hash * hash);
	virtual void updateInitVector() = 0;
	

public:
	virtual ~ChainHash();
	virtual void hashNextBlock(std::string inputA, std::string inputB);
	virtual void hashNextBlock(std::string input);
	virtual void ChainHash::hashNextBlock(unsigned char * input, int length = -1);
	virtual unsigned int * init_vector();
	virtual unsigned int * last_hash();
	virtual void clear();
	const uint32 CHAIN_BLOCK_SIZE;
	const uint32 DIGEST_SIZE;

};

#endif

