// algorithms/xor.cpp
#include "algorithm_interface.h"
#include <string>
#include <vector>
#include <cstdlib>
#include <ctime>
using namespace std;

static string g_resultString;
static vector<unsigned char> g_resultData;

static string xorEncryptDecrypt(const string& text, unsigned char key) {
    string result = text;
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] = (char)((unsigned char)result[i] ^ key);
    }
    return result;
}

static vector<unsigned char> xorEncryptDecryptData(const vector<unsigned char>& data, unsigned char key) {
    vector<unsigned char> result = data;
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] = result[i] ^ key;
    }
    return result;
}

static unsigned char xorGenerateKey() {
    static bool seeded = false;
    if (!seeded) {
        srand(time(nullptr));
        seeded = true;
    }
    return (rand() % 255) + 1;
}
  //exported functions for C interface
extern "C" {

const char* encrypt_text(const char* text, unsigned char key) {
    if (!text) return "";
    g_resultString = xorEncryptDecrypt(string(text), key);
    return g_resultString.c_str();
}

const char* decrypt_text(const char* cipher, unsigned char key) {
    if (!cipher) return "";
    g_resultString = xorEncryptDecrypt(string(cipher), key);
    return g_resultString.c_str();
}

unsigned char* encrypt_data(const unsigned char* data, int dataSize, unsigned char key, int* outSize) {
    if (!data || dataSize <= 0) {
        *outSize = 0;
        return nullptr;
    }
    vector<unsigned char> input(data, data + dataSize);
    g_resultData = xorEncryptDecryptData(input, key);
    *outSize = g_resultData.size();
    return g_resultData.data();
}

unsigned char* decrypt_data(const unsigned char* data, int dataSize, unsigned char key, int* outSize) {
    if (!data || dataSize <= 0) {
        *outSize = 0;
        return nullptr;
    }
    vector<unsigned char> input(data, data + dataSize);
    g_resultData = xorEncryptDecryptData(input, key);
    *outSize = g_resultData.size();
    return g_resultData.data();
}

