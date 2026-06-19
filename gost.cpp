#include "../algorithm_interface.h"
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <algorithm>

using namespace std;


static string s_resultStr; //результат в виде hex-строки
static vector<unsigned char> s_resultBuf; //результат в виде массива байт


static const unsigned char SBOX[8][16] = {
    {4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
    {14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9},
    {5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
    {7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
    {6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
    {4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
    {13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
    {1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12}
};

static unsigned char INV_SBOX[8][16];

static void init_inv_sboxes() {
    static bool is_initialized = false;
    if (is_initialized) return;
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 16; ++j) {
            INV_SBOX[i][SBOX[i][j]] = j;
        }
    }
    is_initialized = true;
}

// циклический сдвиг влево на 11 бит
static unsigned int left_shift_11(unsigned int x) {
    return (x << 11) | (x >> 21);
}

// Битовый циклический сдвиг вправо на 11 бит
static unsigned int right_shift_11(unsigned int x) {
    return (x >> 11) | (x << 21);
}

// Раундовая функция зашифрования 
static unsigned int gost_encrypt_round(unsigned int block, unsigned int key) {
    unsigned int sum = block + key; // Сложение по модулю 2^32

    // Побитовая подстановка (S-boxes)
    unsigned int substituted = 0;
    for (int i = 0; i < 8; ++i) {
        unsigned int nibble = (sum >> (4 * i)) & 0xF; // сдвигаем число вправо на 4*i бит, чтобы нужный полубайт оказался в младших 4 битах. Затем обнуляем все биты, кроме младших 4
        substituted |= (SBOX[i][nibble] << (4 * i));
    }

    return left_shift_11(substituted); // Циклический сдвиг на 11
}

// Раундовая функция расшифрования 
static unsigned int gost_decrypt_round(unsigned int block, unsigned int key) {
    unsigned int shifted = right_shift_11(block); // Обратный сдвиг

    // Обратная подстановка
    unsigned int substituted = 0;
    for (int i = 0; i < 8; ++i) {
        unsigned int nibble = (shifted >> (4 * i)) & 0xF;
        substituted |= (INV_SBOX[i][nibble] << (4 * i));
    }

    return substituted - key; // Вычитание по модулю 2^32
}

// Развертка 8-байтного ключа в 8 раундовых подключей (по 4 байта)
static void expand_key(const unsigned char key[8], unsigned int round_keys[8]) {
    for (int i = 0; i < 8; ++i) {
        round_keys[i] = 0;
        for (int j = 0; j < 4; ++j) {
            round_keys[i] |= (key[(i * 4 + j) % 8] << (8 * j)); //использование этих 8 ключей в 32 раундах (повторяя их)
        }
    }
}
