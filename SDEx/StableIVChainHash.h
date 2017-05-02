#ifndef STABLEIVCHAIN_HASH_H
#define STABLEIVCHAIN_HASH_H
#include "Hash.h"
#include "ChainHash.h"

class StableIVChainHash : public ChainHash
{
protected:
	virtual void updateInitVector();
public:
	StableIVChainHash(Hash * _hash);
	~StableIVChainHash();
};


#endif
