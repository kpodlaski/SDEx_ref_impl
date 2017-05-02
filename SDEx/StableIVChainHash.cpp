#include "stdafx.h"
#include "Hash.h"
#include "ChainHash.h"
#include "StableIVChainHash.h"

void StableIVChainHash::updateInitVector() {
	//DO nothing, IV stays the same all the way.
}

StableIVChainHash::StableIVChainHash(Hash * _hash) : ChainHash(_hash)
{
}


StableIVChainHash::~StableIVChainHash()
{
}
