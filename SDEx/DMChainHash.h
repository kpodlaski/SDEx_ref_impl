#ifndef DMCHAIN_HASH_H
#define DMCHAIN_HASH_H
#include "ChainHash.h"
#include "Hash.h"

//Davies-Meyer type chain hash funcion 
class DMChainHash : public ChainHash
{
protected:
	virtual void updateInitVector();
public:
	DMChainHash(Hash * _hash);
	~DMChainHash();

};

#endif