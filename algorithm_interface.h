#ifndef ALGORITHM_INTERFACE_H
#define ALGORITHM_INTERFACE_H

extern "C" {

const char* encrypt_text(const char* text, unsigned char key);
const char* decrypt_text(const char* cipher, unsigned char key); //шифротекст
unsigned char* encrypt_data(const unsigned char* data, int dataSize, unsigned char key, int* outSize);
unsigned char* decrypt_data(const unsigned char* data, int dataSize, unsigned char key, int* outSize);
unsigned char generate_key();
const char* get_algorithm_name();
void free_memory(void* ptr);

}

#endif
