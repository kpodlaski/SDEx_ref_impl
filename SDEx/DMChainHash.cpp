#include "stdafx.h"
#include "DMChainHash.h"
#include "Hash.h"
#include <iostream>

void DMChainHash::updateInitVector() {
	unsigned char * _niv = (unsigned char *)_next_init_vector;
	unsigned char * _lh = (unsigned char *)_last_hash;
	for (int i = 0; i < hash->IV_SIZE; i++) {
		_next_init_vector[i] = _next_init_vector[i] ^ _last_hash[i];
	}

}


DMChainHash::DMChainHash(Hash * _hash) : ChainHash(_hash)
{
}


DMChainHash::~DMChainHash()
{
}
