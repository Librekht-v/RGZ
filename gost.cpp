#include "algorithm_interface.h"
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

// Шифрование одного 8-байтного блока (Сеть Фейстеля, 32 раунда)
static void encrypt_block(const unsigned char in[8], unsigned char out[8], unsigned int rkeys[8]) {
    unsigned int n1 = 0, n2 = 0;
    for (int i = 0; i < 4; ++i) {
        n1 |= (in[i] << (8 * i)); // Берём 8 байт и разбиваем их на две половинки
        n2 |= (in[i + 4] << (8 * i));
    }

    // Первые 24 раунда: ключи повторяются 3 раза
    for (int r = 0; r < 24; ++r) {
        n1 ^= gost_encrypt_round(n2, rkeys[r % 8]); // Ключи повторяются каждые 8 раундов.
        swap(n1, n2); // Классический обмен половинками в сети Фейстеля
    }

    // ключи в обратном порядке
    for (int r = 0; r < 8; ++r) {
        n1 ^= gost_encrypt_round(n2, rkeys[7 - r]); // XOR
        swap(n1, n2);
    }

    // половинки НЕ меняются местами, надо поменять
    for (int i = 0; i < 4; ++i) {
        out[i] = (n2 >> (8 * i)) & 0xFF;
        out[i + 4] = (n1 >> (8 * i)) & 0xFF;
    }
}

// Расшифрование одного 8-байтного блока
static void decrypt_block(const unsigned char in[8], unsigned char out[8], unsigned int rkeys[8]) {
    unsigned int n1 = 0, n2 = 0;
    for (int i = 0; i < 4; ++i) {
        n1 |= (in[i] << (8 * i));// количество бит, на которое нужно сдвинуть число вправо.
        n2 |= (in[i + 4] << (8 * i));
    }

    // В расшифровании раунды идут в обратном порядке, а ключи — в прямом для первых 8
    for (int r = 0; r < 8; ++r) {
        n1 ^= gost_decrypt_round(n2, rkeys[r]);
        swap(n1, n2);
    }

    for (int r = 0; r < 24; ++r) {
        n1 ^= gost_decrypt_round(n2, rkeys[(23 - r) % 8]);
        swap(n1, n2);
    }

    for (int i = 0; i < 4; ++i) {
        out[i] = (n2 >> (8 * i)) & 0xFF; // 8 единиц
        out[i + 4] = (n1 >> (8 * i)) & 0xFF;
    }
}

// Вспомогательные функции (Паддинг, Hex, Генерация ключа)

static vector<unsigned char> pkcs7_pad(const vector<unsigned char>& data) {
    size_t pad_len = 8 - (data.size() % 8);
    vector<unsigned char> res = data;
    res.insert(res.end(), pad_len, static_cast<unsigned char>(pad_len)); // вставляем в результат N раз N чары 
    return res;
}

static vector<unsigned char> pkcs7_unpad(const vector<unsigned char>& data) {
    if (data.empty()) return {};
    unsigned char pad_len = data.back(); // длина паддинга

if (pad_len > data.size() || pad_len > 8) return data;
    return vector<unsigned char>(data.begin(), data.end() - pad_len);
}

static string bytes_to_hex(const vector<unsigned char>& data) {
    string res;
    res.reserve(data.size() * 2);
    char buf[3];
    for (unsigned char b : data) {
        sprintf(buf, "%02x", b); // означает: 2 символа, шестнадцатеричный вид, с ведущим нулём
        res += buf;
    }
    return res;
}

static vector<unsigned char> hex_to_bytes(const string& hex) {
    vector<unsigned char> res;
    res.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int byte;
        sscanf(hex.c_str() + i, "%02x", &byte); 
        res.push_back(static_cast<unsigned char>(byte));
    }
    return res;
}

static void make_key_from_byte(unsigned char key_byte, unsigned char out_key[8]) {
    for (int i = 0; i < 8; ++i) { // 1 байт ключа в 8 байт
        out_key[i] = key_byte ^ (i * 0x33);
    }
}


static string process_string(const string& text, unsigned char key, bool encrypt) {
    unsigned char raw_key[8];
    make_key_from_byte(key, raw_key);

    unsigned int rkeys[8];
    expand_key(raw_key, rkeys);

    vector<unsigned char> data(text.begin(), text.end());
    if (encrypt) data = pkcs7_pad(data);

    if (!encrypt && data.size() % 8 != 0) return ""; 

    vector<unsigned char> result;
    result.reserve(data.size());

    for (size_t i = 0; i < data.size(); i += 8) {
        unsigned char block[8], processed[8];
        memcpy(block, &data[i], 8); // Копируем 8 байт из вектора data начиная с i в массив block

        if (encrypt) encrypt_block(block, processed, rkeys);  // processed результат шифрования/расшифрования
        else decrypt_block(block, processed, rkeys);

        result.insert(result.end(), processed, processed + 8); // Вставляем все 8 байт из processed в result
    }

    if (!encrypt) result = pkcs7_unpad(result);

    return encrypt ? bytes_to_hex(result) : string(result.begin(), result.end()); // или hex или обычная строка
}

// для обработки байтов, а не строк
static vector<unsigned char> process_data(const vector<unsigned char>& data, unsigned char key, bool encrypt) {
    unsigned char raw_key[8];
    make_key_from_byte(key, raw_key);

    unsigned int rkeys[8];
    expand_key(raw_key, rkeys);

    vector<unsigned char> work_data = data;
    if (encrypt) work_data = pkcs7_pad(work_data);

    if (!encrypt && work_data.size() % 8 != 0) return {};

    vector<unsigned char> result;
    result.reserve(work_data.size());

    for (size_t i = 0; i < work_data.size(); i += 8) {
        unsigned char block[8], processed[8];
        memcpy(block, &work_data[i], 8);

        if (encrypt) encrypt_block(block, processed, rkeys);
        else         decrypt_block(block, processed, rkeys);

        result.insert(result.end(), processed, processed + 8);
    }

    if (!encrypt) result = pkcs7_unpad(result);
    return result;
}

static unsigned char generate_random_key() {
    static bool seeded = false;
    if (!seeded) {
        srand(static_cast<unsigned int>(time(nullptr)));
        seeded = true;
    }
    return (rand() % 255) + 1; // как раз 256 различных 1-байтовых
}

// Инициализация обратных S-блоков при старте программы
static struct AutoInit {
    AutoInit() { init_inv_sboxes(); }
} auto_init;


extern "C" {
// Для шифрования текста
const char* encrypt_text(const char* text, unsigned char key) { //указатель на char строку
    if (!text) return "";
    s_resultStr = process_string(string(text), key, true);
    return s_resultStr.c_str(); // указатель на глобальную строку (стринг в чар)
}

const char* decrypt_text(const char* cipher, unsigned char key) {
    if (!cipher) return "";
    s_resultStr = process_string(string(cipher), key, false);
    return s_resultStr.c_str();
}
// Для шифрования хоть чего
unsigned char* encrypt_data(const unsigned char* data, int dataSize, unsigned char key, int* outSize) {
    if (!data || dataSize <= 0) { *outSize = 0; return nullptr; } // тогда возвращаем пустой указатель
    vector<unsigned char> input(data, data + dataSize); // оот указателя на начало до конца массива
    s_resultBuf = process_data(input, key, true);
    *outSize = s_resultBuf.size();
    return s_resultBuf.data(); //указатель на первый элемент вектора чтобы в Си вернуть сам вектор
}

unsigned char* decrypt_data(const unsigned char* data, int dataSize, unsigned char key, int* outSize) {
    if (!data || dataSize <= 0) { *outSize = 0; return nullptr; }
    vector<unsigned char> input(data, data + dataSize);
    s_resultBuf = process_data(input, key, false);
    *outSize = s_resultBuf.size();
    return s_resultBuf.data();
}

unsigned char generate_key() { return generate_random_key(); }

const char* get_algorithm_name() {
    s_resultStr = "ГОСТ 28147-89 (режим простой замены)";
    return s_resultStr.c_str();
}

void free_memory(void* ptr) {}

}









