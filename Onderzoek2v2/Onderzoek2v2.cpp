// Onderzoek2v2.cpp
// Meet per methode: gemiddelde encrypt- en decrypt/verify-tijd + grootte origineel vs. versleuteld/gehasht bericht.
//
// Projectbestanden: Onderzoek2v2.cpp, Encryption.h, Integrity.h  (Integrity.cpp en RsaCrypto.h zijn niet meer nodig)
//
// Gebruik:  Onderzoek2v2.exe "Mijn testzin" 10000
//           (zonder argumenten vraagt het programma erom)
//
// Zonder OpenSSL (alleen AES + ChaCha20 testen; ook RSA en de MACs vallen dan weg): definieer NO_OPENSSL in de projectinstellingen.

#include <algorithm>
#include <chrono>
#include <functional>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "Encryption.h"
#ifndef NO_OPENSSL
#include "Integrity.h"
#endif

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
        mn = (std::min)(mn, ns);
        mx = (std::max)(mx, ns);
    }
    return { total / runs / 1000.0, mn / 1000.0, mx / 1000.0 };   // in microseconden
}

static void printHeader(const std::string& text, int runs) {
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
}

static void runBenchmark(const Method& m, const std::string& text, int runs) {
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
static std::string verifyMac(const std::string& packet, size_t macLen,
    const std::function<std::string(const std::string&)>& compute) {
    if (packet.size() < macLen) throw std::runtime_error("pakket te klein");
    std::string msg = packet.substr(0, packet.size() - macLen);
    std::string mac = packet.substr(packet.size() - macLen);
    if (compute(msg) != mac) throw std::runtime_error("MAC komt niet overeen");
    return msg;
}
#endif

// =====================================================================
//  main
// =====================================================================
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

    Encryption crypto;
    std::vector<Method> methods;

    // --- Encryptie ---
    methods.push_back({ "AES-256-CBC",
        [&](const std::string& s) { return crypto.aesEncrypt(s); },
        [&](const std::string& c) { return crypto.aesDecrypt(c); } });
    methods.push_back({ "ChaCha20",
        [&](const std::string& s) { return crypto.chacha20Encrypt(s); },
        [&](const std::string& c) { return crypto.chacha20Decrypt(c); } });

#ifndef NO_OPENSSL
    // --- RSA-2048 OAEP (OpenSSL, zit in Encryption.h). Sleutelpaar wordt eenmalig vooraf gemaakt, dus niet meegemeten. ---
    crypto.rsaGenerateKey(2048);
    methods.push_back({ "RSA-2048 OAEP",
        [&](const std::string& s) { return crypto.rsaEncrypt(s); },
        [&](const std::string& c) { return crypto.rsaDecrypt(c); } });

    // --- Integriteit: packet = bericht + mac (hex-tekst); "decrypt" = mac opnieuw berekenen en vergelijken ---
    // Sleutel: 64 hex-tekens, zoals in config.json (hier een vaste testsleutel).
    Integrity integrity("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    auto hmac = [&](const std::string& s) { return integrity.computeHMAC_SHA256(s); };
    auto cmac = [&](const std::string& s) { return integrity.computeCMAC(s); };
    auto poly = [&](const std::string& s) { return integrity.computePoly1305(s); };

    methods.push_back({ "HMAC-SHA256 (hex)",
        [=](const std::string& s) { return s + hmac(s); },
        [=](const std::string& p) { return verifyMac(p, 64, hmac); } });
    methods.push_back({ "CMAC AES-256 (hex)",
        [=](const std::string& s) { return s + cmac(s); },
        [=](const std::string& p) { return verifyMac(p, 32, cmac); } });
    methods.push_back({ "Poly1305 (hex)",
        [=](const std::string& s) { return s + poly(s); },
        [=](const std::string& p) { return verifyMac(p, 32, poly); } });
#endif

    printHeader(text, runs);
    for (const auto& m : methods) runBenchmark(m, text, runs);

    return 0;
}