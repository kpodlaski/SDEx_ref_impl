// SDEx.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include <iostream>
#include "sha256.h"
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include "ChainHash.h"
#include "StableIVChainHash.h"
#include "DMChainHash.h"
#include "SDExCrypt.h"
#include <stdio.h>

using std::string;
using std::cout;
using std::endl;

int reverse_chars_in_int(unsigned int x) {
	int r;
	unsigned char * cx = (unsigned char *) &x;
	unsigned char * cr = (unsigned char *) &r;
	cr[0] = cx[3];
	cr[1] = cx[2];
	cr[2] = cx[1];
	cr[3] = cx[0];
	return r;
}


void main_test_reverse_chars_in_int() {
	unsigned int ho[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
	unsigned int oh[8] = { 0x67e6096a,0x85ae67bb,0x72f36e3c,0x3af54fa5,0x7f520e51,0x8c68059b,0xabd9831f,0x19cde05b };
	unsigned int rh[8];
	for (int i = 0; i < 8; i++)
		rh[i] = reverse_chars_in_int(ho[i]);
	std::cout << "TEST" << std::endl;
	for (int i = 0; i < 8; i++) {
		std::cout <<std::dec<< "expected: " << oh[i] << " obtained: " << rh[i] << std::endl;
		std::cout << std::setfill('0') << std::setw(8) << std::hex << oh[i] << std::endl;
		if (oh[i] == rh[i]) std::cout << "ok" << std::endl;
		else std::cout << "ERROR" << std::endl;
	}
}
// HAS£O:Ala_nie_ma_kota
// IV :Ala_ma_kota

void main_encrypt_test() {
	string message = "Message to be encrypted :12345678901234567891234567890123456789abcdefg01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890Message to be encrypted :12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890Message to be encrypted :12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890Message to be encrypted :12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
	cout << "Encrypt message" << endl;
	std::ifstream inFile;
	inFile.open("test.txt");//open the input file

	std::stringstream ssmessage;
	ssmessage << inFile.rdbuf();//read the file
	message = ssmessage.str();

	SDExCryptAlg * crypt = new SDExCryptAlg(new SHA256(), "Ala_ma_kota", "Ala_nie_ma_kota");
	string encrypted = crypt->crypt(message);
	
	cout << message.length()<<" :: "<<encrypted.length() << endl;
	cout << message.length()/64 <<"b+"<< message.length() % 64 << " :: " << encrypted.length()/64 << "b+" << encrypted.length() % 64<<endl;
	//cout << encrypted << endl;
	std::ofstream plik;
	plik.open("crypt2", std::ios_base::binary | std::ios_base::out);
	plik << encrypted;
	plik.close();


	SDExCryptAlg * decrypt = new SDExCryptAlg(new SHA256(), "Ala_ma_kota", "Ala_nie_ma_kota");
	string decrypted = decrypt->decrypt(encrypted);
	plik.open("decrypted", std::ios_base::binary | std::ios_base::out);
	plik << decrypted;
	plik.close();
}

void main_chainhash_test() {
	unsigned int iv[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
	string input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	cout << " ----- StableIVChainHash ---" << endl;
	ChainHash*  chash = new StableIVChainHash( new SHA256());
	unsigned char * digest = new unsigned char[chash->DIGEST_SIZE];
	memset(digest, 0, chash->DIGEST_SIZE);
	for (int i = 0; i < 10; i++)
	{
		string output1 = chash->hashNextBlock(input);
		cout << "sha256('" << input << "'):" << output1 << endl;
	}
	cout << " ----- DMChainHash ---"<<endl;
	delete chash;
	for (int x = 0; x < 2; x++) {
		cout << " ----- run " << x << " ---" << endl;
		
		chash = new DMChainHash(new SHA256());
		for (int i = 0; i < 10; i++)
		{
			string output1 = chash->hashNextBlock(input);
			cout << "sha256('" << input << "'):" << output1 << endl;
		}
		delete chash;
	}
}

void main_chainhash_NIST_test() {
	cout << "Hash with NIST examples" << endl;
	//Examples from http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf , APPENDIX B: SHA-256 EXAMPLES 
	unsigned int iv[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
	ChainHash*  chash = new DMChainHash(new SHA256());
	unsigned char * digest = new unsigned char[chash->DIGEST_SIZE];
	memset(digest, 0, chash->DIGEST_SIZE);
	string input = "abc";
	string output1 = chash->hashNextBlock(input);
	cout << "input:" << input << endl;
	cout << "obtained hash:" << output1 << endl;
	cout << "expected hash:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" << endl;
	cout << "::::::" << endl;
	input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	chash = new DMChainHash(new SHA256());
	output1 = chash->hashNextBlock(input);
	cout << "input:" << input << endl;
	cout << "obtained hash:" << output1 << endl;
	cout << "expected hash:248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" << endl;
	std::ifstream inFile;
	inFile.open("test.txt");//open the input file
	std::stringstream ssmessage;
	ssmessage << inFile.rdbuf();//read the file
	input = ssmessage.str();
	chash = new DMChainHash(new SHA256());
	output1 = chash->hashNextBlock(input);
	cout << "input: 1,000,000 of 'a'" << endl;
	cout << "obtained hash:" << output1 << endl;
	cout << "expected hash:cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0" << endl;
	cout << "::::::::::::::::::::::::::::::::::::" << endl;
	cout << "::::::::::::::::::::::::::::::::::::" << endl;
	input = "Ala_ma_kota";
	chash = new DMChainHash(new SHA256());
	output1 = chash->hashNextBlock(input);
	cout << "IV:Ala_ma_kota" << endl;
	cout << "H_IV:" << output1 << endl;
	cout << "::::::::::::::::::::::::::::::::::::" << endl;
	input = "Ala_nie_ma_kota";
	chash = new DMChainHash(new SHA256());
	output1 = chash->hashNextBlock(input);
	cout << "U:Ala_nie_ma_kota" << endl;
	cout << "H_U:" << output1 << endl;
	
	/*unsigned char * digest = (unsigned char*) iv;
	for (int i = 0; i < 256 / 8; i++) {
	cout << std::dec <<(int)digest[i] << " == " <<std::setfill('0') << std::setw(2) << std::hex << (int)digest[i] << endl;
	}
	*/
}

void main_sha256_NIST_test() {
	//Examples from http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf , APPENDIX B: SHA-256 EXAMPLES 
	unsigned int iv[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
	string input = "abc";
	string output1 = sha256(iv, 8, input);
	cout << "input:" << input << endl;
	cout << "obtained hash:" << output1 << endl;
	cout << "expected hash:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"<< endl;
	cout << "::::::" << endl;
	input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	output1 = sha256(iv, 8, input);
	cout << "input:" << input << endl;
	cout << "obtained hash:" << output1 << endl;
	cout << "expected hash:248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" << endl;
	std::ifstream inFile;
	inFile.open("test.txt");//open the input file
	std::stringstream ssmessage;
	ssmessage << inFile.rdbuf();//read the file
	input = ssmessage.str();
	output1 = sha256(iv, 8, input);
	cout << "input: 1,000,000 of 'a'" << endl;
	cout << "obtained hash:" << output1 << endl;
	cout << "expected hash:cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0" << endl;


	/*unsigned char * digest = (unsigned char*) iv;
	for (int i = 0; i < 256 / 8; i++) {
	cout << std::dec <<(int)digest[i] << " == " <<std::setfill('0') << std::setw(2) << std::hex << (int)digest[i] << endl;
	}
	*/
}


void main_sha256_test3() {
	unsigned int iv[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
	string input = "grape";
	string output1 = sha256(iv,8,input);
	cout << "sha256('" << input << "'):" << output1 << endl;

	/*unsigned char * digest = (unsigned char*) iv;
	for (int i = 0; i < 256 / 8; i++) {
		cout << std::dec <<(int)digest[i] << " == " <<std::setfill('0') << std::setw(2) << std::hex << (int)digest[i] << endl;
	}
	*/
}

void main_sha256_test() {
	string input = "grape";
	string output1 = sha256(input);
	cout << "sha256('" << input << "'):" << output1 << endl;
}

void main_sha256_test2() {
	SHA256 ctx = SHA256();
	for (int i = 0; i < 10; i++) {
		string input = "grape";
		unsigned char * digest =new unsigned char[ctx.DIGEST_SIZE];
		memset(digest, 0, ctx.DIGEST_SIZE);


		ctx.init();
		ctx.update((unsigned char*)input.c_str(), input.length());
		ctx.final(digest);
		std::stringstream ss;

		char * buf = new char[2 * ctx.DIGEST_SIZE + 4];
		buf[2 * ctx.DIGEST_SIZE] = 0;
		for (int i = 0; i < ctx.DIGEST_SIZE; i++)
			ss << std::setfill('0') << std::setw(2) << std::hex << (int)digest[i];
		string output1 = ss.str();
		cout << "sha256('" << input << "'):" << output1 << endl;
		delete[] digest;
		delete[] buf;
	}
}



void main_test_t() {
	unsigned int  x = 0x6a09e667;
	std::cout << std::dec<<  x<<std::endl;
	std::cout << std::setfill('0') << std::setw(8) << std::hex << x;
	std::cout << std::endl;
	unsigned char * c = (unsigned char *) &x;
	for (int i = 0; i< 4; i++)
		std::cout << std::setfill('0') << std::setw(2) << std::hex << (short) c[i];
	std::cout << std::endl;
	x = 0x67e6096a;
	std::cout << std::dec << x << std::endl;
	std::cout << std::setfill('0') << std::setw(8) << std::hex << x;
	std::cout << std::endl;
	c = (unsigned char *)&x;
	for (int i = 0; i< 4; i++)
		std::cout << std::setfill('0') << std::setw(2) << std::hex << (short)c[i] ;
	std::cout << std::endl;
	bool* b = (bool *)&x;
	std::cout << std::dec;
	for (int i = 0; i < 32; i++) {
		if (b[i]) std::cout << 1;
		else std::cout << 0;
	}
	std::cout << std::endl;
	unsigned int y = 0xa5e3125f;
	unsigned int z = 0;
	unsigned char * c2 = (unsigned char *)&y;
	unsigned char * r = (unsigned char *)&z;
	std::cout << ((unsigned int) x^y) << std::endl;
	for (int i = 0; i < 4; i++)
		r[i] = c[i] ^ c2[i];
		
	std::cout << z << std::endl;



}

int main()
{
	//main_sha256_test();
	//cout << "------------------------------------"<< endl;
	//main_sha256_test2();
	//cout << "------------------------------------" << endl;
	//main_sha256_test3();
	//cout << "------------------------------------" << endl;
	//main_chainhash_test();
	//cout << "------------------------------------" << endl;
	//main_sha256_NIST_test();
	//cout << "------------------------------------" << endl;
	//main_chainhash_NIST_test();
	//cout << "------------------------------------" << endl;
	//main_test_t();
	//main_test_reverse_chars_in_int();
	
	main_encrypt_test();
	system("pause");

}

