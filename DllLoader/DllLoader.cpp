// DllLoader.cpp : Defines the entry point for the console application.
//

#define WIN32_LEAN_AND_MEAN
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <assert.h>
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <malloc.h>

#include "MemoryModule.h"

//#define CTR 1
//#include "aes.hpp"

#include <iostream>
#include <iomanip>
#include <cstdio>
#include <fstream>

/*
#include "cryptlib.h"
#include "filters.h"
#include "files.h"
#include "modes.h"
#include "hex.h"
#include "aes.h"
using namespace CryptoPP;
*/

#include "encrypt.h"

using namespace std;

#define DLL_FILE TEXT("MyDll.dll")

const string g_defaultKey = "jdb623efud";



int RunFromMemory(void)
{
	FILE *fp;
	unsigned char *data = NULL;
	long size;
	size_t read;
	HMEMORYMODULE handle;
	int result = -1;

	fp = _tfopen(DLL_FILE, _T("rb"));
	if (fp == NULL)
	{
		_tprintf(_T("Can't open executable \"%s\"."), DLL_FILE);
		goto exit;
	}

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	assert(size >= 0);
	data = (unsigned char *)malloc(size);
	assert(data != NULL);
	fseek(fp, 0, SEEK_SET);
	read = fread(data, 1, size, fp);
	assert(read == static_cast<size_t>(size));
	fclose(fp);

	handle = MemoryLoadLibrary(data, size);
	if (handle == NULL)
	{
		_tprintf(_T("Can't load library from memory.\n"));
		goto exit;
	}

	result = MemoryCallEntryPoint(handle);
	if (result < 0) {
		_tprintf(_T("Could not execute entry point: %d\n"), result);
	}
	MemoryFreeLibrary(handle);

exit:
	free(data);
	return result;
}


static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";


static inline bool is_base64(unsigned char c) {
	return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
	std::string ret;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];

	while (in_len--) {
		char_array_3[i++] = *(bytes_to_encode++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (i = 0; (i <4); i++)
				ret += base64_chars[char_array_4[i]];
			i = 0;
		}
	}

	if (i)
	{
		for (j = i; j < 3; j++)
			char_array_3[j] = '\0';

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (j = 0; (j < i + 1); j++)
			ret += base64_chars[char_array_4[j]];

		while ((i++ < 3))
			ret += '=';

	}

	return ret;

}
//
//std::string base64_decode(std::string const& encoded_string) {
//	int in_len = encoded_string.size();
//	int i = 0;
//	int j = 0;
//	int in_ = 0;
//	unsigned char char_array_4[4], char_array_3[3];
//	std::string ret;
//
//	while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
//		char_array_4[i++] = encoded_string[in_]; in_++;
//		if (i == 4) {
//			for (i = 0; i <4; i++)
//				char_array_4[i] = base64_chars.find(char_array_4[i]);
//
//			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
//			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
//			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
//
//			for (i = 0; (i < 3); i++)
//				ret += char_array_3[i];
//			i = 0;
//		}
//	}
//
//	if (i) {
//		for (j = i; j <4; j++)
//			char_array_4[j] = 0;
//
//		for (j = 0; j <4; j++)
//			char_array_4[j] = base64_chars.find(char_array_4[j]);
//
//		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
//		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
//		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
//
//		for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
//	}
//
//	return ret;
//}


void testEncryption();
void encryptFile();
void decryptFile();
void loadEncryptedDll();


int main()
{

	//struct AES_ctx ctx;

	//char* key = "hnr2892adfdthf";

	////char* buffer = "The quick brown fox jumps over the lazy dog";
	//char* buffer = "123456789abcdefg";
	//
	//int bufferSize = 16;

	//AES_init_ctx(&ctx, (uint8_t*) key);

	//// encrypt
	//printf("encrypting...");
	//AES_CTR_xcrypt_buffer( &ctx, (uint8_t*) buffer, bufferSize);

	//// decrypt
	//printf("decrypting...");
	//AES_CTR_xcrypt_buffer(&ctx, (uint8_t*)buffer, bufferSize);

	//printf("decrypted buffer:\n%s", buffer);


	//return 0;



	try {

		cout << "Enter option:\n";
		cout << "1 - encrypt file\n";
		cout << "2 - decrypt file\n";
		cout << "3 - test encryption\n";
		cout << "4 - load encrypted dll\n";

		int option;
		cin >> option;

		if (1 == option) {
			encryptFile();
		}
		else if (2 == option) {
			decryptFile();
		}
		else if (3 == option) {
			testEncryption();
		}
		else if (4 == option) {
			loadEncryptedDll();
		}

	}
	catch (exception& ex) {
		cout << "error:\n" << ex.what();
	}

	return 0;


	//return RunFromMemory();
}

std::vector<char> loadFileIntoMemory(const string& filePath)
{

	std::ifstream file(filePath, std::ios::binary | std::ios::ate);
	if(!file.is_open())
		throw std::exception("failed to open file");

	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);

	std::vector<char> buffer(size);
	if (file.read(buffer.data(), size))
	{
		/* worked! */
		return buffer;
	}

	throw std::exception("failed to read file");
}

void writeDataToFile(const string& filePath, const string& data)
{

	ofstream f;
	f.open(filePath, ios::out | ios::binary | ios::trunc);
	if (!f.is_open())
		throw std::exception("failed to open file");

	f.write(data.data(), data.size());

	f.close();

}

string testEncryption(string& msg, string& key)
{

	string encryptedMsg = encrypt(msg, key);
//	printf("encrypted msg: %s\n\n", encryptedMsg.c_str());

	string decryptedMsg = decrypt(encryptedMsg, key);
//	printf("decrypted msg: %s\n\n", decryptedMsg.c_str());

	return decryptedMsg;
}

void testEncryption()
{

	string key;
	cout << "enter key:\n";
	cin >> key;

	//string msg = "The quick brown fox jumps over the lazy dog";

	auto originalData = loadFileIntoMemory("myfile.txt");

	auto data = originalData;
	cout << "file loaded - num bytes " << data.size() << "\n\n";
//	data.push_back(0);	// so that string can be constructed

//	string originalString = data.data();
	string encodedMsg = base64_encode((unsigned char const*)data.data(), data.size());

	string decryptedMsg = testEncryption(encodedMsg, key);
	
	string decodedMsg = base64_decode(decryptedMsg);

	cout << "decoded message [" << decodedMsg.size() << "]\n";
//	cout << decodedMsg << "\n\n";

	// compare decoded message with original data

	if ( decodedMsg.size() != originalData.size() || memcmp(decodedMsg.data(), originalData.data(), originalData.size() ) != 0)
	{
		cout << "original data and new data are not the same !!!\n\n";
	}
	else
	{
		cout << "success !!!\n\n";
	}

//	cout << "original data:\n" << originalString.c_str() << "\n";

}

void encryptFile()
{

	string fileName = "myfile.txt";
	string key = g_defaultKey;

	cout << "encrypting " << fileName << endl;

	auto data = loadFileIntoMemory(fileName);

	string encodedData = base64_encode((unsigned char*)data.data(), data.size());

	string encryptedData = encrypt(encodedData, key);

	// write encrypted data to new file

	string newFileName = fileName + ".enc";

	writeDataToFile(newFileName, encryptedData);

	cout << "encrypted file: " << newFileName << endl;

}

string decryptFile(const string& fileName, const string& key)
{

	// load data from file

	auto data = loadFileIntoMemory(fileName);

	string encryptedData = string(data.data(), data.size());

	// decrypt

	string decryptedData = decrypt(encryptedData, (string&) key);

	// decode

	string decodedData = base64_decode(decryptedData);

	return decodedData;

}

void decryptFile()
{

	string fileName = "myfile.txt.enc";

	cout << "decrypting " << fileName << endl;

	string decryptedData = decryptFile(fileName, g_defaultKey);

	// write decrypted data to new file

	string newFileName = fileName + ".dec";

	writeDataToFile(newFileName, decryptedData);

	cout << "decrypted file: " << newFileName << endl;

}

void loadEncryptedDll()
{

	string dllName = "myfile.txt.enc";
	string key = g_defaultKey;
	
	cout << "decrypting" << endl;

	string decryptedData = decryptFile(dllName, key);

	cout << "loading dll" << endl;

	HMEMORYMODULE hMemModule = MemoryLoadLibrary(decryptedData.data(), decryptedData.size());

	if (NULL == hMemModule) {
		throw std::exception("Failed to load library from memory");
	}

	cout << "dll loaded" << endl;

	cout << "press key to unload it" << endl;
	cin.get();
	cin.get();

	MemoryFreeLibrary(hMemModule);

	cout << "dll unloaded" << endl;

}

