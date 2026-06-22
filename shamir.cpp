#include "../algorithm_interface.h"
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <ctime>
using namespace std;

static string g_resultString;
static vector<unsigned char> g_resultData;

static int g_n = 5; 
static int g_k = 3; 

static int getPrime(unsigned char key) { 
    const int primes[] = {257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373};
    int idx = key % (sizeof(primes) / sizeof(primes[0]));
    return primes[idx];
}

static int modPow(int a, int e, int mod) {
    int res = 1;
    a %= mod;
    while (e > 0) {
        if (e & 1) res = (res * a) % mod; // если текущий бит равен 1, умножаем результат
        a = (a * a) % mod;
        e >>= 1;
    }
    return res;
}

static int modInv(int a, int mod) { // обратный элемент по модулю a*x mod = 1
    return modPow(a, mod - 2, mod);
}

static string shamirEncryptString(const string& text, unsigned char key) { // 
    int P = getPrime(key); // ← БЫЛО ПРОПУЩЕНО
    int len = text.length();
    vector<vector<int>> shares(g_n, vector<int>(len)); // cоздаёт матрицу g_n × len для хранения фрагментов
    
    srand(time(nullptr));
    
    for (int pos = 0; pos < len; ++pos) {
        int secret = (unsigned char)text[pos]; // берём код символа как секрет
        vector<int> coeff(g_k); // cтроим полином с коэфициентами, где 1 член - секрет, остальные случайные
        coeff[0] = secret;
        for (int i = 1; i < g_k; ++i) { 
            coeff[i] = rand() % (P - 1) + 1;
        }
        for (int i = 0; i < g_n; ++i) { // вычисляем его значение
            int x = i + 1;
            int y = 0, xPow = 1;
            for (int j = 0; j < g_k; ++j) {
                y = (y + coeff[j] * xPow) % P; // на каждом шаге прибавляем
                xPow = (xPow * x) % P;
            }
            shares[i][pos] = y; // сохраняем значение фрагмента
        }
    }
    
    string result = to_string(g_n) + "," + to_string(g_k) + "," + to_string(P) + "|";
    for (int i = 0; i < g_n; ++i) { 
        for (int pos = 0; pos < len; ++pos) { // добавляем значения для всех символов
            if (pos != 0) result += ",";
            result += to_string(shares[i][pos]);
        }
        if (i != g_n - 1) result += ";";
    }
    return result;
}

static string shamirDecryptString(const string& data, unsigned char key) { 
    size_t firstSep = data.find('|'); // позиция разделителя
    if (firstSep == string::npos) return ""; // если нет |
    
    string header = data.substr(0, firstSep); // строка до разделителя(с n,p,k)
    string sharesData = data.substr(firstSep + 1); // строка после разделителя (все элементы)
    
    size_t pos1 = header.find(',');
    size_t pos2 = header.find(',', pos1 + 1);
    int n = stoi(header.substr(0, pos1));
    int k = stoi(header.substr(pos1 + 1, pos2 - pos1 - 1)); // подстрока между 1 и 2 запятыми
    int P = stoi(header.substr(pos2 + 1));
    
    vector<vector<int>> shares;
    size_t start = 0;
    while (start < sharesData.size()) {
        size_t end = sharesData.find(';', start); // находим конец текущего фрагмента
        if (end == string::npos) end = sharesData.size();
        
        string shareStr = sharesData.substr(start, end - start); // извлекаем подстроку
        vector<int> values;
        size_t vStart = 0;
        while (vStart < shareStr.size()) { // разбиваем строку по запятым
            size_t vEnd = shareStr.find(',', vStart);
            if (vEnd == string::npos) vEnd = shareStr.size();
            values.push_back(stoi(shareStr.substr(vStart, vEnd - vStart)));
            vStart = vEnd + 1;
        }
        shares.push_back(values); // сохраняем
        start = end + 1;
    }
    
    if (shares.empty() || shares[0].empty()) return "";
    if (shares.size() < (size_t)k) return ""; // не хватает фрагментов
    
    int len = shares[0].size(); 
    string result(len, ' ');
    
    for (int pos = 0; pos < len; ++pos) { // интерполяция лагранжа
        int secret = 0;
        for (int i = 0; i < k; ++i) { 
            int xi = i + 1; // точка где вычисляется полином
            int yi = shares[i][pos]; // значение полинома в точке
            int li = 1;
            for (int j = 0; j < k; ++j) {
                if (i == j) continue; // все точки кроме i-й
                int xj = j + 1; 
                li = (li * ((0 - xj + P) % P) % P * modInv((xi - xj + P) % P, P)) % P;
            }
            secret = (secret + yi * li) % P; // суммируем
        }
        result[pos] = (char)secret; // число в символ и сохраняем в строку
    }
    return result;
}

static vector<unsigned char> shamirEncryptData(const vector<unsigned char>& data, unsigned char key) {
    int P = getPrime(key);
    vector<unsigned char> result;
    
    for (int i = 0; i < 4; ++i) result.push_back((g_n >> (i * 8)) & 0xFF);  // разбиваем числа по 4 байта
    for (int i = 0; i < 4; ++i) result.push_back((g_k >> (i * 8)) & 0xFF);
    for (int i = 0; i < 4; ++i) result.push_back((P >> (i * 8)) & 0xFF);
    
    int len = data.size();
    vector<vector<int>> shares(g_n, vector<int>(len));
    
    srand(time(nullptr));
    
    for (int pos = 0; pos < len; ++pos) {
        int secret = data[pos]; // берём байт как секрет
        vector<int> coeff(g_k); 
        coeff[0] = secret;
        for (int i = 1; i < g_k; ++i) {
            coeff[i] = rand() % (P - 1) + 1;
        }
        for (int i = 0; i < g_n; ++i) {
            int x = i + 1;
            int y = 0, xPow = 1;
            for (int j = 0; j < g_k; ++j) {
                y = (y + coeff[j] * xPow) % P;
                xPow = (xPow * x) % P;
            }
            shares[i][pos] = y;
        }
    }
    
    for (int i = 0; i < g_n; ++i) { // для каждого фрагмента
        int shareSize = len * 4; // размер в байтах
        for (int j = 0; j < 4; ++j) result.push_back((shareSize >> (j * 8)) & 0xFF);
        for (int pos = 0; pos < len; ++pos) { // для каждого значения фрагмента
            int val = shares[i][pos];
            for (int j = 0; j < 4; ++j) {
                result.push_back((val >> (j * 8)) & 0xFF);
            }
        }
    }
    return result;
}

static vector<unsigned char> shamirDecryptData(const vector<unsigned char>& data, unsigned char key) {
    if (data.size() < 12) return {}; // мин размер
    
    int n = 0, k = 0, P = 0; // считываем заголовок
    for (int i = 0; i < 4; ++i) n |= data[i] << (i * 8);
    for (int i = 0; i < 4; ++i) k |= data[4 + i] << (i * 8);
    for (int i = 0; i < 4; ++i) P |= data[8 + i] << (i * 8);
    
    size_t pos = 12; // ← БЫЛА ПРОПУЩЕНА ТОЧКА С ЗАПЯТОЙ
    vector<vector<int>> shares;
    
    for (int i = 0; i < n && pos < data.size(); ++i) {
        int shareSize = 0; // считываем размер фрагмента
        for (int j = 0; j < 4 && pos < data.size(); ++j) shareSize |= data[pos++] << (j * 8);
        int numValues = shareSize / 4;  // количество значений в фрагменте
        vector<int> values; // считываем каждое значение и добавляем в вектор
        for (int v = 0; v < numValues && pos < data.size(); ++v) {
            int val = 0;
            for (int j = 0; j < 4 && pos < data.size(); ++j) val |= data[pos++] << (j * 8);
            values.push_back(val);  // добавляем значение
        }
        shares.push_back(values); // добавляем фрагмент
    }
    
    if (shares.empty() || shares[0].empty()) return {};
    if (shares.size() < (size_t)k) return {}; // не хватает фрагментов
    
    int len = shares[0].size();     // интерполяцию Лагранжа 
    vector<unsigned char> result(len);
    
    for (int posVal = 0; posVal < len; ++posVal) {
        int secret = 0;
        for (int i = 0; i < k && i < (int)shares.size(); ++i) {
            int xi = i + 1;
            int yi = shares[i][posVal];
            int li = 1;
            for (int j = 0; j < k && j < (int)shares.size(); ++j) {
                if (i == j) continue;
                int xj = j + 1;
                li = (li * ((0 - xj + P) % P) % P * modInv((xi - xj + P) % P, P)) % P;
            }
            secret = (secret + yi * li) % P;
        }
        result[posVal] = (unsigned char)secret;
    }
    return result;
}

static unsigned char shamirGenerateKey() {
    static bool seeded = false;
    if (!seeded) {
        srand(time(nullptr));
        seeded = true;
    }
    return (rand() % 255) + 1;
}

extern "C" {

const char* encrypt_text(const char* text, unsigned char key) { // указатель на с строку и ключ
    if (!text) return ""; 
    g_resultString = shamirEncryptString(string(text), key); 
    return g_resultString.c_str(); // возвращаем указатель на результат
}

const char* decrypt_text(const char* cipher, unsigned char key) { // зашифрованный текст 
    if (!cipher) return "";
    g_resultString = shamirDecryptString(string(cipher), key);
    return g_resultString.c_str();
}

unsigned char* encrypt_data(const unsigned char* data, int dataSize, unsigned char key, int* outSize) { // принимает указатель на бин данные и размер
    if (!data || dataSize <= 0) {
        *outSize = 0; // размер результата
        return nullptr;
    }
    vector<unsigned char> input(data, data + dataSize); // копируем
    g_resultData = shamirEncryptData(input, key);
    *outSize = g_resultData.size();
    return g_resultData.data(); // возвращаем указатель на результат и размер
}

unsigned char* decrypt_data(const unsigned char* data, int dataSize, unsigned char key, int* outSize) {
    if (!data || dataSize <= 0) { 
        *outSize = 0;
        return nullptr;
    }
    vector<unsigned char> input(data, data + dataSize); // копируем данные в вектор
    g_resultData = shamirDecryptData(input, key);
    *outSize = g_resultData.size(); // записываем размер указателя
    return g_resultData.data();
}

unsigned char generate_key() {
    return shamirGenerateKey();
}

const char* get_algorithm_name() {
    g_resultString = "Схема разделения секрета Шамира";
    return g_resultString.c_str();
}

void free_memory(void* ptr) {}

}
