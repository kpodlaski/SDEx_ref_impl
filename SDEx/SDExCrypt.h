#ifndef SDEXCRYPT_H
#define SDEXCRYPT_H

#include "DMChainHash.h"
#include "Hash.h"


class SDExCryptAlg
{

private:
	int block_crypted;

protected:
	DMChainHash * chainHash;
	unsigned int * H_IV;
	unsigned int * H_U;

	unsigned char * inputOdd;
	unsigned char * inputEven;

	virtual void first_block_cypher(const char * inputBlock, unsigned int size, unsigned int * outputBlock);
	virtual void block_cypher(const char * inputBlock, unsigned int size, unsigned int * outputBlock);
	virtual void divide_input_into_subblocks(const char * inputBlock, unsigned int size);
	virtual void first_block_decypher(const char * inputBlock, unsigned int size, unsigned int * outputBlock);
	virtual void block_decypher(const char * inputBlock, unsigned int size, unsigned int * outputBlock);

public:
	SDExCryptAlg(Hash * _hash,std::string IV, std::string U);
	virtual std::string crypt(std::string message);
	virtual std::string decrypt(std::string message);
	~SDExCryptAlg();
};

#endif