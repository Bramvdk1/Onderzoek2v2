// Benchmark.cpp
// Meet per methode: gemiddelde encrypt- en decrypt/verify-tijd + grootte origineel vs. versleuteld/gehasht bericht.
// De AES- en ChaCha20-functies zijn 1-op-1 overgenomen uit Client1.cpp (Encryptie Overhead).
// De MAC-methodes (HMAC / CMAC / Poly1305) komen uit jouw Integrity.cpp (OpenSSL 3.x).
//
// Gebruik:  Benchmark.exe "Mijn testzin" 10000
//           (zonder argumenten vraagt het programma erom)
//
// Zonder OpenSSL (alleen AES + ChaCha20 testen): definieer NO_OPENSSL in de projectinstellingen.

#include <winsock2.h>   // vóór windows.h, net als in je clients
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

#ifndef NO_OPENSSL
#include "Integrity.h"   // voeg Integrity.cpp + Integrity.h toe aan het project (zelfde OpenSSL-instellingen als OverheadOfintegrity)
#endif

// =====================================================================
//  AES-256-CBC  (overgenomen uit AES/Client1/Client1.cpp)
// =====================================================================
BYTE AES_KEY[32] = {
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
};
BYTE AES_IV[16] = {
    10,20,30,40,50,60,70,80,90,100,110,120,130,140,150,160
};

std::string aes_encrypt(const std::string& plain) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    DWORD keyObjLen = 0, dataLen = 0, encLen = 0;
    PUCHAR keyObj = nullptr;
    PUCHAR enc = nullptr;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjLen,
        sizeof(DWORD), &dataLen, 0);

    keyObj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, keyObjLen);

    BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj, keyObjLen,
        AES_KEY, sizeof(AES_KEY), 0);

    // CBC past de IV in-place aan, dus per aanroep een verse kopie gebruiken
    // (in je client gebeurt dit niet, waardoor de 2e encryptie een andere IV krijgt).
    BYTE iv[16];
    memcpy(iv, AES_IV, sizeof(iv));
    BCryptEncrypt(hKey, (PUCHAR)plain.data(), (ULONG)plain.size(), nullptr,
        iv, sizeof(iv), nullptr, 0, &encLen, BCRYPT_BLOCK_PADDING);

    enc = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, encLen);

    memcpy(iv, AES_IV, sizeof(iv));
    BCryptEncrypt(hKey, (PUCHAR)plain.data(), (ULONG)plain.size(), nullptr,
        iv, sizeof(iv), enc, encLen, &dataLen, BCRYPT_BLOCK_PADDING);

    std::string out((char*)enc, dataLen);

    if (enc) HeapFree(GetProcessHeap(), 0, enc);
    if (keyObj) HeapFree(GetProcessHeap(), 0, keyObj);
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return out;
}


std::string aes_decrypt(const std::string& cipher) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    DWORD keyObjLen = 0, dataLen = 0, decLen = 0;
    PUCHAR keyObj = nullptr;
    PUCHAR dec = nullptr;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjLen,
        sizeof(DWORD), &dataLen, 0);

    keyObj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, keyObjLen);

    BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj, keyObjLen,
        AES_KEY, sizeof(AES_KEY), 0);

    BYTE iv[16];
    memcpy(iv, AES_IV, sizeof(iv));
    BCryptDecrypt(hKey, (PUCHAR)cipher.data(), (ULONG)cipher.size(), nullptr,
        iv, sizeof(iv), nullptr, 0, &decLen, BCRYPT_BLOCK_PADDING);

    dec = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, decLen);

    memcpy(iv, AES_IV, sizeof(iv));
    BCryptDecrypt(hKey, (PUCHAR)cipher.data(), (ULONG)cipher.size(), nullptr,
        iv, sizeof(iv), dec, decLen, &dataLen, BCRYPT_BLOCK_PADDING);

    std::string out((char*)dec, dataLen);

    if (dec) HeapFree(GetProcessHeap(), 0, dec);
    if (keyObj) HeapFree(GetProcessHeap(), 0, keyObj);
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return out;
}

// =====================================================================
//  ChaCha20  (overgenomen uit ChaCha20/Client1/Client1.cpp)
// =====================================================================
BYTE CHACHA_KEY[32] = {
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
};

static inline uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static inline void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl(d, 16);
    c += d; b ^= c; b = rotl(b, 12);
    a += b; d ^= a; d = rotl(d, 8);
    c += d; b ^= c; b = rotl(b, 7);
}

static void chacha20_block(const uint32_t key[8], const uint32_t counter, const uint32_t nonce[3], BYTE out[64]) {
    static const uint32_t constants[4] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };

    uint32_t state[16];
    uint32_t working[16];
    state[0] = constants[0];
    state[1] = constants[1];
    state[2] = constants[2];
    state[3] = constants[3];
    for (int i = 0; i < 8; ++i) state[4 + i] = key[i];
    state[12] = counter;
    state[13] = nonce[0];
    state[14] = nonce[1];
    state[15] = nonce[2];

    memcpy(working, state, sizeof(state));

    for (int i = 0; i < 10; ++i) {
        quarter_round(working[0], working[4], working[8], working[12]);
        quarter_round(working[1], working[5], working[9], working[13]);
        quarter_round(working[2], working[6], working[10], working[14]);
        quarter_round(working[3], working[7], working[11], working[15]);
        quarter_round(working[0], working[5], working[10], working[15]);
        quarter_round(working[1], working[6], working[11], working[12]);
        quarter_round(working[2], working[7], working[8], working[13]);
        quarter_round(working[3], working[4], working[9], working[14]);
    }

    for (int i = 0; i < 16; ++i) {
        uint32_t res = working[i] + state[i];
        out[i * 4 + 0] = (BYTE)(res & 0xff);
        out[i * 4 + 1] = (BYTE)((res >> 8) & 0xff);
        out[i * 4 + 2] = (BYTE)((res >> 16) & 0xff);
        out[i * 4 + 3] = (BYTE)((res >> 24) & 0xff);
    }
}

static void chacha20_xor_stream(const BYTE key32[32], const BYTE nonce12[12], uint32_t counter,
    const BYTE* in, BYTE* out, size_t len) {
    uint32_t key_words[8];
    uint32_t nonce_words[3];

    for (int i = 0; i < 8; ++i) {
        key_words[i] = (uint32_t)key32[i * 4 + 0]
            | ((uint32_t)key32[i * 4 + 1] << 8)
            | ((uint32_t)key32[i * 4 + 2] << 16)
            | ((uint32_t)key32[i * 4 + 3] << 24);
    }
    for (int i = 0; i < 3; ++i) {
        nonce_words[i] = (uint32_t)nonce12[i * 4 + 0]
            | ((uint32_t)nonce12[i * 4 + 1] << 8)
            | ((uint32_t)nonce12[i * 4 + 2] << 16)
            | ((uint32_t)nonce12[i * 4 + 3] << 24);
    }

    BYTE block[64];
    size_t offset = 0;
    uint32_t ctr = counter;

    while (offset < len) {
        chacha20_block(key_words, ctr, nonce_words, block);
        size_t chunk = (len - offset > 64) ? 64 : (len - offset);
        for (size_t i = 0; i < chunk; ++i) {
            out[offset + i] = in[offset + i] ^ block[i];
        }
        offset += chunk;
        ++ctr;
    }

    SecureZeroMemory(block, sizeof(block));
    SecureZeroMemory(key_words, sizeof(key_words));
    SecureZeroMemory(nonce_words, sizeof(nonce_words));
}

// Formaat: [12-byte nonce][ciphertext]
std::string chacha20_encrypt(const std::string& plain) {
    BYTE nonce[12];
    NTSTATUS st = BCryptGenRandom(NULL, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0) return std::string();

    std::vector<BYTE> cipher(plain.size());
    chacha20_xor_stream(CHACHA_KEY, nonce, 1, (const BYTE*)plain.data(), cipher.data(), plain.size());

    std::string out;
    out.reserve(12 + cipher.size());
    out.append((char*)nonce, 12);
    out.append((char*)cipher.data(), cipher.size());

    SecureZeroMemory(cipher.data(), cipher.size());
    return out;
}


std::string chacha20_decrypt(const std::string& cipher) {
    if (cipher.size() < 12) return std::string();
    const BYTE* nonce = (const BYTE*)cipher.data();
    const BYTE* ct = (const BYTE*)cipher.data() + 12;
    size_t ctlen = cipher.size() - 12;

    std::vector<BYTE> plain(ctlen);
    chacha20_xor_stream(CHACHA_KEY, nonce, 1, ct, plain.data(), ctlen);
    std::string out((char*)plain.data(), ctlen);

    SecureZeroMemory(plain.data(), plain.size());
    return out;
}

// =====================================================================
//  Benchmark
// =====================================================================
struct Method {
    std::string name;
    // encrypt: zin -> bytes die over het netwerk gaan (versleuteld, of bericht + mac)
    std::function<std::string(const std::string&)> encrypt;
    // decrypt: ontvangen bytes -> originele zin (bij MAC: controleert de mac, gooit bij mismatch)
    std::function<std::string(const std::string&)> decrypt;
};

using Clock = std::chrono::steady_clock;

struct Stats { double avg, mn, mx; };

static Stats measure(int runs, const std::function<void()>& op) {
    op();   // warm-up
    double total = 0, mn = 1e300, mx = 0;
    for (int i = 0; i < runs; ++i) {
        auto t0 = Clock::now();
        op();
        auto t1 = Clock::now();
        double ns = (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
        total += ns;
        mn = std::min(mn, ns);
        mx = std::max(mx, ns);
    }
    return { total / runs / 1000.0, mn / 1000.0, mx / 1000.0 };   // in microseconden
}

static void run_benchmark(const Method& m, const std::string& text, int runs) {
    try {
        std::string packet = m.encrypt(text);
        std::string back = m.decrypt(packet);
        bool ok = (back == text);

        std::string sink;   // voorkomt dat de compiler het resultaat wegoptimaliseert
        Stats enc = measure(runs, [&] { sink = m.encrypt(text); });
        Stats dec = measure(runs, [&] { sink = m.decrypt(packet); });

        long long overhead = (long long)packet.size() - (long long)text.size();
        std::cout << std::left << std::setw(20) << m.name
            << std::right << std::setw(6) << text.size() << " B"
            << std::setw(6) << packet.size() << " B"
            << std::setw(6) << std::showpos << overhead << std::noshowpos << " B"
            << std::fixed << std::setprecision(3)
            << std::setw(12) << enc.avg
            << std::setw(12) << dec.avg
            << std::setw(12) << enc.mn << std::setw(10) << enc.mx
            << std::setw(12) << dec.mn << std::setw(10) << dec.mx
            << "   " << (ok ? "OK" : "FOUT") << "\n";
    }
    catch (const std::exception& e) {
        std::cout << std::left << std::setw(20) << m.name << " FOUT: " << e.what() << "\n";
    }
}

#ifndef NO_OPENSSL
// Controleert een pakket "bericht + hex-mac": splitst, berekent de mac opnieuw, vergelijkt.
static std::string verify_mac(const std::string& packet, size_t macLen,
    const std::function<std::string(const std::string&)>& compute) {
    if (packet.size() < macLen) throw std::runtime_error("pakket te klein");
    std::string msg = packet.substr(0, packet.size() - macLen);
    std::string mac = packet.substr(packet.size() - macLen);
    if (compute(msg) != mac) throw std::runtime_error("MAC komt niet overeen");
    return msg;
}
#endif

int main(int argc, char* argv[]) {
    std::string text;
    int runs = 0;

    if (argc >= 3) {
        text = argv[1];
        runs = std::atoi(argv[2]);
    }
    else {
        std::cout << "Zin om te testen: ";
        std::getline(std::cin, text);
        std::cout << "Aantal tests: ";
        std::cin >> runs;
    }
    if (runs <= 0) { std::cerr << "Aantal tests moet > 0 zijn.\n"; return 1; }

    std::vector<Method> methods;

    // --- Encryptie: zelfde functies als in je clients ---
    methods.push_back({ "AES-256-CBC",
        [](const std::string& s) { return aes_encrypt(s); },
        [](const std::string& c) { return aes_decrypt(c); } });
    methods.push_back({ "ChaCha20",
        [](const std::string& s) { return chacha20_encrypt(s); },
        [](const std::string& c) { return chacha20_decrypt(c); } });

#ifndef NO_OPENSSL
    // --- Integriteit: packet = bericht + mac (hex-tekst), zoals in TCPClient.cpp ---
    // "Decrypt" = het pakket splitsen, de mac opnieuw berekenen en vergelijken.
    // Sleutel: 64 hex-tekens, zoals in config.json (hier een vaste testsleutel).
    static Integrity integrity("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    auto hmac = [](const std::string& s) { return integrity.computeHMAC_SHA256(s); };
    auto cmac = [](const std::string& s) { return integrity.computeCMAC(s); };
    auto poly = [](const std::string& s) { return integrity.computePoly1305(s); };

    methods.push_back({ "HMAC-SHA256 (hex)",
        [=](const std::string& s) { return s + hmac(s); },
        [=](const std::string& p) { return verify_mac(p, 64, hmac); } });
    methods.push_back({ "CMAC AES-256 (hex)",
        [=](const std::string& s) { return s + cmac(s); },
        [=](const std::string& p) { return verify_mac(p, 32, cmac); } });
    methods.push_back({ "Poly1305 (hex)",
        [=](const std::string& s) { return s + poly(s); },
        [=](const std::string& p) { return verify_mac(p, 32, poly); } });
#endif

    std::cout << "\nZin: \"" << text << "\"\n"
        << "Aantal tests per methode: " << runs << "\n"
        << "Tijden in microseconden (us). Bij MACs is 'Decrypt' = mac verifieren.\n\n";

    std::cout << std::left << std::setw(20) << "Methode"
        << std::right << std::setw(8) << "Orig."
        << std::setw(8) << "Result."
        << std::setw(8) << "Overh."
        << std::setw(12) << "Enc gem."
        << std::setw(12) << "Dec gem."
        << std::setw(12) << "Enc min" << std::setw(10) << "Enc max"
        << std::setw(12) << "Dec min" << std::setw(10) << "Dec max"
        << "   Klopt\n";
    std::cout << std::string(124, '-') << "\n";

    for (const auto& m : methods) run_benchmark(m, text, runs);

    return 0;
}