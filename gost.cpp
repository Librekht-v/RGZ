#include "../algorithm_interface.h"
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <iostream>
using namespace std;

static string g_resultString; //результат в виде hex-строки
static vector<unsigned char> g_resultData; //результат в виде массива байт

static const unsigned char SBox[8][16] = {
    {4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
    {14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9},
    {5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
    {7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
    {6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
    {4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
    {13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
    {1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12}
};

static unsigned char InvSBox[8][16];

static void initInvSBoxes() { // Инициализация обратных S-блоков при старте программы
    static bool initialized = false;
    if (initialized) return;
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 16; j++) {
            InvSBox[i][SBox[i][j]] = j;
        }
    }
    initialized = true;
}

// циклический сдвиг влево на 11 бит
static unsigned int leftRotate11(unsigned int x) {
    return (x << 11) | (x >> (32 - 11));
}

// Битовый циклический сдвиг вправо на 11 бит
static unsigned int rightRotate11(unsigned int x) {
    return (x >> 11) | (x << (32 - 11));
}

// Раундовая функция зашифрования 
static unsigned int gostRound(unsigned int n, unsigned int key) {
    unsigned int sum = n + key; // Сложение по модулю 2^32

    // Побитовая подстановка (S-boxes)
    unsigned int replaced = 0;
    for (int i = 0; i < 8; i++) {
        unsigned int nibble = (sum >> (4 * i)) & 0xF; // сдвигаем число вправо на 4*i бит, чтобы нужный полубайт оказался в младших 4 битах. Затем обнуляем все биты, кроме младших 4
        replaced |= (SBox[i][nibble] << (4 * i));
    }

    return leftRotate11(replaced); // Циклический сдвиг на 11
}

// Раундовая функция расшифрования 
static unsigned int gostInvRound(unsigned int n, unsigned int key) {
    unsigned int rotated = rightRotate11(n); // Обратный сдвиг

    // Обратная подстановка
    unsigned int replaced = 0;
    for (int i = 0; i < 8; i++) {
        unsigned int nibble = (rotated >> (4 * i)) & 0xF;
        replaced |= (InvSBox[i][nibble] << (4 * i));
    }

    return replaced - key; // Вычитание по модулю 2^32
}

// Развертка 8-байтного ключа в 8 раундовых подключей (по 4 байта)
static void expandKey(unsigned char key[8], unsigned int roundKeys[8]) {
    for (int i = 0; i < 8; i++) {
        roundKeys[i] = 0;
        for (int j = 0; j < 4; j++) {
            int byteIndex = (i * 4 + j) % 8;
            roundKeys[i] |= (key[byteIndex] << (8 * j)); //использование этих 8 ключей в 32 раундах (повторяя их)
        }
    }
}

// Шифрование одного 8-байтного блока (Сеть Фейстеля, 32 раунда)
static void encryptBlock(const unsigned char input[8], unsigned char output[8], unsigned int roundKeys[8]) {
    unsigned int left = 0, right = 0;
    for (int i = 0; i < 4; i++) {
        left |= (input[i] << (8 * i)); // Берём 8 байт и разбиваем их на две половинки
        right |= (input[i + 4] << (8 * i));
    }

    // Первые 24 раунда: ключи повторяются 3 раза
    for (int round = 0; round < 24; round++) {
        unsigned int newLeft = right;
        unsigned int newRight = left ^ gostRound(right, roundKeys[round % 8]); // Ключи повторяются каждые 8 раундов.
        left = newLeft;
        right = newRight; // Классический обмен половинками в сети Фейстеля
    }

    // ключи в обратном порядке
    for (int round = 0; round < 8; round++) {
        unsigned int newLeft = right;
        unsigned int newRight = left ^ gostRound(right, roundKeys[7 - round]); // XOR
        left = newLeft;
        right = newRight;
    }

    // половинки НЕ меняются местами, надо поменять
    for (int i = 0; i < 4; i++) {
        output[i] = (left >> (8 * i)) & 0xFF;
        output[i + 4] = (right >> (8 * i)) & 0xFF;
    }
}

// Расшифрование одного 8-байтного блока
static void decryptBlock(const unsigned char input[8], unsigned char output[8], unsigned int roundKeys[8]) {
    unsigned int left = 0, right = 0;
    for (int i = 0; i < 4; i++) {
        left |= (input[i] << (8 * i));// количество бит, на которое нужно сдвинуть число вправо.
        right |= (input[i + 4] << (8 * i));
    }

    // В расшифровании раунды идут в обратном порядке, а ключи — в прямом для первых 8
    unsigned int keySeq[32];
    int idx = 0;
    for (int round = 0; round < 24; round++) {
        keySeq[idx++] = roundKeys[round % 8];
    }
    for (int round = 0; round < 8; round++) {
        keySeq[idx++] = roundKeys[7 - round];
    }

    for (int i = 31; i >= 0; i--) {
        unsigned int newRight = left;
        unsigned int newLeft = right ^ gostRound(newRight, keySeq[i]);
        left = newLeft;
        right = newRight;
    }

    for (int i = 0; i < 4; i++) {
        output[i] = (left >> (8 * i)) & 0xFF; // 8 единиц
        output[i + 4] = (right >> (8 * i)) & 0xFF;
    }
}

// Вспомогательные функции (Паддинг, Hex, Генерация ключа)

// ПРОСТОЙ ПАДДИНГ БЕЗ PKCS#7 (чтобы не путался с данными)
static vector<unsigned char> simplePad(const vector<unsigned char>& data) {
    vector<unsigned char> padded = data;
    size_t padLen = 8 - (data.size() % 8);
    if (padLen != 8) {
        padded.insert(padded.end(), padLen, 0x00); // вставляем в результат N раз N чары 
    }
    return padded;
}

static vector<unsigned char> simpleUnpad(const vector<unsigned char>& data, size_t originalSize) {
    if (data.size() <= originalSize) {
        return data;
    }
    vector<unsigned char> result(data.begin(), data.begin() + originalSize);
    return result;
}

static string bytesToHex(const vector<unsigned char>& data) {
    stringstream ss;
    ss << hex << setfill('0');
    for (unsigned char byte : data) {
        ss << setw(2) << (int)byte; // означает: 2 символа, шестнадцатеричный вид, с ведущим нулём
    }
    return ss.str();
}

static vector<unsigned char> hexToBytes(const string& hex) {
    vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        bytes.push_back((unsigned char)stoi(byteString, nullptr, 16)); 
    }
    return bytes;
}

static void expandKeyByte(unsigned char keyByte, unsigned char expandedKey[8]) {
    for (int i = 0; i < 8; i++) { // 1 байт ключа в 8 байт
        expandedKey[i] = keyByte ^ (i * 0x33);
    }
}

static string gostEncryptString(const string& text, unsigned char key) {
    unsigned char rawKey[8];
    expandKeyByte(key, rawKey);
    
    unsigned int roundKeys[8];
    expandKey(rawKey, roundKeys);
    
    vector<unsigned char> plain(text.begin(), text.end());
    vector<unsigned char> padded = simplePad(plain);
    
    vector<unsigned char> cipher;
    for (size_t i = 0; i < padded.size(); i += 8) {
        unsigned char block[8], encrypted[8];
        memcpy(block, &padded[i], 8); // Копируем 8 байт из вектора data начиная с i в массив block

        encryptBlock(block, encrypted, roundKeys);  // encrypted результат шифрования/расшифрования

        cipher.insert(cipher.end(), encrypted, encrypted + 8); // Вставляем все 8 байт из encrypted в cipher
    }
    
    return bytesToHex(cipher); // или hex или обычная строка
}

static string gostDecryptString(const string& cipherHex, unsigned char key) {
    vector<unsigned char> cipher = hexToBytes(cipherHex);
    
    unsigned char rawKey[8];
    expandKeyByte(key, rawKey);
    
    unsigned int roundKeys[8];
    expandKey(rawKey, roundKeys);
    
    if (cipher.size() % 8 != 0) return "";
    
    vector<unsigned char> plain;
    for (size_t i = 0; i < cipher.size(); i += 8) {
        unsigned char block[8], decrypted[8];
        memcpy(block, &cipher[i], 8);

        decryptBlock(block, decrypted, roundKeys);

        plain.insert(plain.end(), decrypted, decrypted + 8);
    }
    
    // Удаляем нулевой паддинг
    while (!plain.empty() && plain.back() == 0x00) {
        plain.pop_back();
    }
    
    return string(plain.begin(), plain.end());
}

// для обработки байтов, а не строк
static vector<unsigned char> gostEncryptData(const vector<unsigned char>& data, unsigned char key) {
    unsigned char rawKey[8];
    expandKeyByte(key, rawKey);
    
    unsigned int roundKeys[8];
    expandKey(rawKey, roundKeys);
    
    vector<unsigned char> result;
    
    // 1. Сохраняем исходный размер (4 байта, little-endian)
    uint32_t originalSize = (uint32_t)data.size();
    for (int i = 0; i < 4; ++i) {
        result.push_back((originalSize >> (i * 8)) & 0xFF);
    }
    
    // 2. Паддинг и шифрование
    vector<unsigned char> padded = simplePad(data);
    vector<unsigned char> cipher;
    
    for (size_t i = 0; i < padded.size(); i += 8) {
        unsigned char block[8], encrypted[8];
        memcpy(block, &padded[i], 8);

        encryptBlock(block, encrypted, roundKeys);

        cipher.insert(cipher.end(), encrypted, encrypted + 8);
    }
    
    // 3. Добавляем зашифрованные данные
    result.insert(result.end(), cipher.begin(), cipher.end());
    return result;
}

static vector<unsigned char> gostDecryptData(const vector<unsigned char>& data, unsigned char key) {
    // 1. Проверяем минимальный размер
    if (data.size() < 12) {
        cerr << "ОШИБКА: размер данных меньше 12 байт" << endl;
        return {};
    }
    
    // 2. Читаем исходный размер (первые 4 байта)
    uint32_t originalSize = 0;
    for (int i = 0; i < 4; ++i) {
        originalSize |= (uint32_t)data[i] << (i * 8);
    }
    
    cerr << "=== ОТЛАДКА ===" << endl;
    cerr << "Исходный размер: " << originalSize << " байт" << endl;
    cerr << "Размер данных: " << data.size() << " байт" << endl;
    
    // 3. Проверяем, что размер корректен
    if (originalSize > data.size() - 4) {
        cerr << "ОШИБКА: размер из заголовка (" << originalSize 
             << ") больше данных (" << data.size() - 4 << ")" << endl;
        return {};
    }
    
    if ((data.size() - 4) % 8 != 0) {
        cerr << "ОШИБКА: данные не кратны 8" << endl;
        return {};
    }
    
    unsigned char rawKey[8];
    expandKeyByte(key, rawKey);
    
    unsigned int roundKeys[8];
    expandKey(rawKey, roundKeys);
    
    // 4. Дешифруем данные (начиная с 4-го байта)
    vector<unsigned char> cipher(data.begin() + 4, data.end());
    vector<unsigned char> plain;
    
    for (size_t i = 0; i < cipher.size(); i += 8) {
        unsigned char block[8], decrypted[8];
        memcpy(block, &cipher[i], 8);

        decryptBlock(block, decrypted, roundKeys);

        plain.insert(plain.end(), decrypted, decrypted + 8);
    }
    
    // 5. Убираем нулевой паддинг
    while (!plain.empty() && plain.back() == 0x00) {
        plain.pop_back();
    }
    
    // 6. ОБЯЗАТЕЛЬНО обрезаем до исходного размера
    if (plain.size() > originalSize) {
        plain.resize(originalSize);
        cerr << "Обрезано до: " << plain.size() << " байт" << endl;
    }
    
    cerr << "=== КОНЕЦ ОТЛАДКИ ===" << endl;
    return plain;
}

static unsigned char gostGenerateKey() {
    static bool seeded = false;
    if (!seeded) {
        srand(time(nullptr));
        seeded = true;
    }
    return (rand() % 255) + 1; // как раз 256 различных 1-байтовых
}

// Инициализация обратных S-блоков при старте программы
static struct Init {
    Init() {
        initInvSBoxes();
    }
} init;

extern "C" {
// Для шифрования текста
const char* encrypt_text(const char* text, unsigned char key) { //указатель на char строку
    if (!text) return "";
    g_resultString = gostEncryptString(string(text), key);
    return g_resultString.c_str(); // указатель на глобальную строку (стринг в чар)
}

const char* decrypt_text(const char* cipher, unsigned char key) {
    if (!cipher) return "";
    g_resultString = gostDecryptString(string(cipher), key);
    return g_resultString.c_str();
}

// Для шифрования хоть чего
unsigned char* encrypt_data(const unsigned char* data, int dataSize, unsigned char key, int* outSize) {
    if (!data || dataSize <= 0) { *outSize = 0; return nullptr; } // тогда возвращаем пустой указатель
    vector<unsigned char> input(data, data + dataSize); // от указателя на начало до конца массива
    g_resultData = gostEncryptData(input, key);
    *outSize = g_resultData.size();
    return g_resultData.data(); //указатель на первый элемент вектора чтобы в Си вернуть сам вектор
}

unsigned char* decrypt_data(const unsigned char* data, int dataSize, unsigned char key, int* outSize) {
    if (!data || dataSize <= 0) { *outSize = 0; return nullptr; }
    vector<unsigned char> input(data, data + dataSize);
    g_resultData = gostDecryptData(input, key);
    *outSize = g_resultData.size();
    
    if (g_resultData.empty()) {
        *outSize = 0;
        return nullptr;
    }
    
    return g_resultData.data();
}

unsigned char generate_key() { return gostGenerateKey(); }

const char* get_algorithm_name() {
    g_resultString = "ГОСТ 28147-89 (режим простой замены)";
    return g_resultString.c_str();
}

void free_memory(void* ptr) {}

}