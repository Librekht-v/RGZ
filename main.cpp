#include <iostream>
#include <string>
#include <vector>
#include <fstream> // Для работы с файлами (ifstream, ofstream)
#include <filesystem> // Для работы с папками и путями
#include <limits> //очистка cin
#include <stdexcept> // для исключений 
#include <clocale>
#include "library_loader.h"

using namespace std;
namespace fs = filesystem;

// Глобальные переменные 
static LibraryLoader loader;                              // Загрузчик DLL библиотек
static const vector<AlgorithmFunctions>* algorithms = nullptr;  // Список загруженных алгоритмов
static int current_algo = -1;                             // Номер текущего выбранного алгоритма

// Очистка потока ввода (если пользователь ввёл букву вместо числа)
void clear_input() {
    cin.clear();                                          // Сбрасываем флаг ошибки
    cin.ignore(numeric_limits<streamsize>::max(), '\n');  // Удаляем всё до конца строки
}

// Ожидание нажатия Enter
void wait_enter() {
    cout << "\nНажмите Enter для продолжения...";
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
}

// Получить название текущего алгоритма
string get_algo_name() {
    if (!algorithms || current_algo < 0 || current_algo >= (int)algorithms->size()) {
        return "Не выбран";
    }
    return (*algorithms)[current_algo].name;
}

// Ввод ключа (общая функция для текста и файлов)
unsigned char input_key() {
    cout << "Введите ключ (1-255) или Enter для генерации: ";
    string key_str;
    getline(cin, key_str); // читает до Enter
    
    // Если пользователь просто нажал Enter - генерируем ключ
    if (key_str.empty()) {
        unsigned char key = (*algorithms)[current_algo].generate_key();
        cout << "Сгенерирован ключ: " << (int)key << endl;
        return key;
    }
    
    // Иначе пытаемся превратить строку в число
    try {
        int key_int = stoi(key_str);
        if (key_int < 1 || key_int > 255) {
            throw runtime_error("Ключ должен быть от 1 до 255");
        }
        return (unsigned char)key_int;
    } catch (...) { // любая ошибка
        throw runtime_error("Неверный формат ключа");
    }
}

// 1. Работа с текстом (шифрование/дешифрование)
void work_with_text() {
    try {
        cout << "\nРАБОТА С ТЕКСТОМ" << endl;
        cout << "Алгоритм: " << get_algo_name() << endl;
        cout << "1. Зашифровать\n2. Расшифровать\nВыбор: ";
        
        int choice;
        cin >> choice;
        if (cin.fail()) throw runtime_error("Введите число 1 или 2");
        clear_input();
        
        if (choice != 1 && choice != 2) throw runtime_error("Неверный выбор");
        
        cout << "Введите текст: ";
        string text;
        getline(cin, text); 
        if (text.empty()) throw runtime_error("Текст пустой");
        
        unsigned char key = input_key();
        
        // Вызываем функцию из DLL напрямую
        string result;
        if (choice == 1) {
            result = (*algorithms)[current_algo].encrypt_text(text.c_str(), key);
            cout << "\nЗашифрованный текст:\n" << result << endl;
        } else {
            result = (*algorithms)[current_algo].decrypt_text(text.c_str(), key);
            cout << "\nРасшифрованный текст:\n" << result << endl;
        }
    } catch (const exception& e) { //ссылка на объект ошибки
        clear_input();
        cerr << "[ОШИБКА] " << e.what() << endl;
    }
    wait_enter();
}

// 2. Работа с файлом (шифрование/дешифрование)
void work_with_file() {
    try {
        cout << "\nРАБОТА С ФАЙЛОМ" << endl;
        cout << "Алгоритм: " << get_algo_name() << endl;
        cout << "1. Зашифровать\n2. Расшифровать\nВыбор: ";
        
        int choice;
        cin >> choice;
        if (cin.fail()) throw runtime_error("Введите число 1 или 2");
        clear_input();
        
        if (choice != 1 && choice != 2) throw runtime_error("Неверный выбор");
        
        unsigned char key = input_key();
        
        cout << "Путь к файлу: ";
        string path;
        getline(cin, path);
        if (path.empty()) throw runtime_error("Путь пустой");
        
        // Проверяем существование файла 
        if (!fs::exists(path)) {
            cout << "Файл не найден. Создать? (y/n): ";
            string ans;
            getline(cin, ans);
            if (ans == "y" || ans == "Y") {
                // Создаём папки если нужно
                fs::path p(path); // объект пути
                if (p.has_parent_path() && !fs::exists(p.parent_path())) {
                    fs::create_directories(p.parent_path());
                    cout << "Создана папка: " << p.parent_path().string() << endl;
                }
                // Создаём пустой файл
                ofstream new_file(path, ios::binary); //пишем что нужно и что угодно бинарником
                if (!new_file) throw runtime_error("Не удалось создать файл");
                new_file.close();
                cout << "Файл создан" << endl;
            } else {
                throw runtime_error("Операция отменена");
            }
        }
        
        // Читаем файл в вектор байт
        ifstream in_file(path, ios::binary);
        if (!in_file) throw runtime_error("Не удалось открыть файл");
        
        vector<unsigned char> data((istreambuf_iterator<char>(in_file)), istreambuf_iterator<char>()); // читаем файл побайтово
        in_file.close();
        
        if (data.empty()) throw runtime_error("Файл пустой");
        cout << "Размер: " << data.size() << " байт" << endl;
        
        // Шифруем или дешифруем
        int out_size = 0;
        unsigned char* result_ptr = nullptr;
        
        if (choice == 1) {
            result_ptr = (*algorithms)[current_algo].encrypt_data(data.data(), data.size(), key, &out_size); // итератор с первого байта даты
        } else {
            result_ptr = (*algorithms)[current_algo].decrypt_data(data.data(), data.size(), key, &out_size);
        }
        
        if (!result_ptr || out_size <= 0) throw runtime_error("Ошибка обработки");
        
        // Копируем результат в вектор
        vector<unsigned char> result(result_ptr, result_ptr + out_size);
        
        // Формируем имя выходного файла
        string out_path = path + (choice == 1 ? ".encrypted" : ".decrypted");
        
        // Записываем результат в файл
        ofstream out_file(out_path, ios::binary);
        if (!out_file) throw runtime_error("Не удалось создать выходной файл");
        
        out_file.write((char*)result.data(), result.size()); //записываем  result.size() байт в файл
        out_file.close();
        
        cout << "Результат сохранён: " << out_path << endl;
    } catch (const exception& e) {
        clear_input();
        cerr << "[ОШИБКА] " << e.what() << endl;
    }
    wait_enter();
}

// 3. Генерация ключа
void generate_key_menu() {
    try {
        cout << "\n=== ГЕНЕРАЦИЯ КЛЮЧА ===" << endl;
        cout << "Алгоритм: " << get_algo_name() << endl;
        
        unsigned char key = (*algorithms)[current_algo].generate_key();
        cout << "Ключ: " << (int)key << endl;
    } catch (const exception& e) {
        cerr << "[ОШИБКА] " << e.what() << endl;
    }
    wait_enter();
}

// 4. Список алгоритмов
void show_algorithms() {
    cout << "\n=== АЛГОРИТМЫ ===" << endl;
    if (!algorithms || algorithms->empty()) {
        cout << "Нет загруженных алгоритмов" << endl;
    } else {
        for (int i = 0; i < (int)algorithms->size(); i++) {
            cout << (i + 1) << ". " << (*algorithms)[i].name << endl;
        }
    }
    cout << "Текущий: " << get_algo_name() << endl;
    wait_enter();
}

// 5. Выбор алгоритма
void select_algorithm() {
    try {
        cout << "\n=== ВЫБОР АЛГОРИТМА ===" << endl;
        if (!algorithms || algorithms->empty()) throw runtime_error("Нет алгоритмов");
        
        for (int i = 0; i < (int)algorithms->size(); i++) {
            cout << (i + 1) << ". " << (*algorithms)[i].name << endl;
        }
        
        cout << "Выбор (1-" << algorithms->size() << "): ";
        int choice;
        cin >> choice;
        if (cin.fail()) throw runtime_error("Введите число");
        clear_input();
        
        if (choice < 1 || choice > (int)algorithms->size()) throw runtime_error("Неверный номер");
        
        current_algo = choice - 1;
        cout << "Выбран: " << get_algo_name() << endl;
    } catch (const exception& e) {
        clear_input();
        cerr << "[ОШИБКА] " << e.what() << endl;
    }
    wait_enter();
}

// Главная функция - точка входа в программу
int main() {
    setlocale(LC_ALL, "Russian");  // Включаем русский язык
    
    cout << "Загрузка алгоритмов..." << endl;
    
    // Создаём папку algorithms если её нет
    if (!fs::exists("./algorithms")) {
        fs::create_directory("./algorithms");
        cout << "Создана папка ./algorithms" << endl;
        cout << "Поместите туда .so файлы и перезапустите" << endl;
        return 0;
    }
    
    // Загружаем все библиотеки из папки
    if (!loader.loadAlgorithmsFromFolder("./algorithms")) {
        cout << "Ошибка загрузки" << endl;
        return 1;
    }
    
    algorithms = &loader.getAlgorithms();
    
    if (algorithms->empty()) {
        cout << "Нет алгоритмов в папке" << endl;
        return 1;
    }
    
    cout << "Загружено: " << algorithms->size() << " алгоритмов" << endl;
    current_algo = 0;  // Выбираем первый по умолчанию
    cout << "По умолчанию: " << get_algo_name() << endl;
    
    
    while (true) {
        cout << "\n" << endl;
        cout << "   CryptRGR" << endl;
        cout << " " << endl;
        cout << "Алгоритм: " << get_algo_name() << endl;
        cout << " " << endl;
        cout << "1. Работа с текстом" << endl;
        cout << "2. Работа с файлом" << endl;
        cout << "3. Генерация ключа" << endl;
        cout << "4. Список алгоритмов" << endl;
        cout << "5. Выбрать алгоритм" << endl;
        cout << "6. Выход" << endl;
        cout << " " << endl;
        cout << "Выбор: ";
        
        int choice;
        cin >> choice;
        
        if (cin.fail()) {
            clear_input();
            cout << "Ошибка: введите число" << endl;
            continue;
        }
        clear_input();
        
        switch (choice) {
            case 1: work_with_text(); break;
            case 2: work_with_file(); break;
            case 3: generate_key_menu(); break;
            case 4: show_algorithms(); break;
            case 5: select_algorithm(); break;
            case 6: 
                cout << "Выход..." << endl;
                return 0;
            default:
                cout << "Ошибка: выберите 1-6" << endl;
        }
    }
}