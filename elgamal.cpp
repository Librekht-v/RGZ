#ifndef ELGAMAL_CORE_H
#define ELGAMAL_CORE_H

#include <string>
#include <vector>
#include <cstdlib>
#include <ctime>
using namespace std;

static string g_resultString;
static vector<unsigned char> g_resultData;

static long long modPow(long long base, long long exp, long long mod) {
    long long result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

static long long modInverse(long long a, long long mod) {
    long long t = 0, newT = 1;
    long long r = mod, newR = a;
    while (newR != 0) {
        long long quotient = r / newR;
        long long tmpT = t;
        t = newT;
        newT = tmpT - quotient * newT;
        long long tmpR = r;
        r = newR;
        newR = tmpR - quotient * newR;
    }
    if (t < 0) t += mod;
    return t;
}

static void generateParams(unsigned char key, long long& p, long long& g, long long& y, long long& x) {
    const long long primes[] = {257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373};
    int index = key % 20;
    p = primes[index];
    g = 2;
    x = (key % (p - 2)) + 1;
    y = modPow(g, x, p);
}

static unsigned char elgamalGenerateKey() {
    static bool seeded = false;
    if (!seeded) {
        srand(time(nullptr));
        seeded = true;
    }
    return (rand() % 255) + 1;
}

#endif
