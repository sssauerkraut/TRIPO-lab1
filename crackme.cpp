#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>
#include <stdint.h>

#ifdef _MSC_VER
  #define NOINLINE __declspec(noinline)
#else
  #define NOINLINE __attribute__((noinline))
#endif

// Прототипы функций
void secure_printf(unsigned char* enc_str, int str_len);
FILE* secure_fopen(unsigned char* enc_filename, int filename_len, const char* mode);
void GenerateJokes(void);
void ShowSuccessWindow(void);
void ShowErrorWindow(void);
NOINLINE int Check_passw(void);
NOINLINE void Check_passw_end(void);
int PasswordCheckSilent(void);
int VerifyIntegrity(void);

// простая CRC32 (пример)
uint32_t crc32(const unsigned char *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320;
            else crc >>= 1;
        }
    }
    return ~crc;
}


#define PASSWORD "september2025"
#define MAX_LEN 50
#define KEY_LEN 10

// Зашифрованные строки
static unsigned char enc_PASSWORD[] = {41, 166, 14, 46, 166, 19, 56, 166, 12, 104, 243, 76, 111, 195};
static unsigned char enc_PASSFILE[] = {42, 162, 13, 41, 180, 17, 40, 167, 80, 46, 187, 10, 90};
static unsigned char enc_SERIALFILE[] = {41, 166, 12, 51, 162, 18, 116, 183, 6, 46, 195};
static unsigned char enc_JOKESFILE[] = {48, 172, 21, 63, 176, 33, 61, 166, 16, 63, 177, 31, 46, 166, 26, 116, 183, 6, 46, 195};
static unsigned char enc_JOKES_HEADER[] = {9, 140, 51, 31, 227, 52, 21, 136, 59, 9, 201, 116, 90};
static unsigned char enc_MSG_SUCCESS_1[] = {10, 162, 13, 41, 180, 17, 40, 167, 94, 57, 172, 12, 40, 166, 29, 46, 226, 116, 80, 144, 27, 40, 170, 31, 54, 227, 16, 47, 174, 28, 63, 177, 94, 61, 166, 16, 63, 177, 31, 46, 166, 26, 122, 162, 16, 62, 227, 13, 59, 181, 27, 62, 227, 23, 52, 227, 13, 63, 177, 23, 59, 175, 80, 46, 187, 10, 122, 165, 23, 54, 166, 126};
static unsigned char enc_MSG_SUCCESS_2[] = {9, 182, 29, 57, 166, 13, 41, 195};
static unsigned char enc_MSG_ERROR_1[] = {13, 177, 17, 52, 164, 94, 42, 162, 13, 41, 180, 17, 40, 167, 95, 80, 201, 61, 50, 166, 29, 49, 227, 14, 59, 176, 13, 45, 172, 12, 62, 237, 10, 34, 183, 94, 60, 170, 18, 63, 227, 31, 52, 167, 94, 46, 177, 7, 122, 162, 25, 59, 170, 16, 116, 195};
static unsigned char enc_MSG_ERROR_2[] = {31, 177, 12, 53, 177, 126};
static unsigned char enc_MSG_START[] = {9, 183, 31, 40, 183, 23, 52, 164, 94, 42, 162, 13, 41, 180, 17, 40, 167, 94, 57, 171, 27, 57, 168, 94, 42, 177, 17, 61, 177, 31, 55, 237, 80, 116, 201, 126};
static unsigned char enc_MSG_READ[] = {8, 166, 31, 62, 170, 16, 61, 227, 14, 59, 176, 13, 45, 172, 12, 62, 227, 24, 40, 172, 19, 122, 179, 31, 41, 176, 9, 53, 177, 26, 116, 183, 6, 46, 227, 24, 51, 175, 27, 116, 237, 80, 80, 195};
static unsigned char enc_MSG_COMPLETE[] = {10, 177, 17, 61, 177, 31, 55, 227, 29, 53, 174, 14, 54, 166, 10, 63, 167, 80, 122, 147, 12, 63, 176, 13, 122, 134, 16, 46, 166, 12, 122, 183, 17, 122, 166, 6, 51, 183, 80, 116, 237, 116, 90};
static unsigned char enc_MSG_SERIAL_CREATED[] = {9, 166, 12, 51, 162, 18, 122, 173, 11, 55, 161, 27, 40, 227, 29, 40, 166, 31, 46, 166, 26, 96, 227, 126};
static unsigned char enc_MSG_JOKES_CREATED[] = {27, 167, 26, 51, 183, 23, 53, 173, 31, 54, 249, 94, 48, 172, 21, 63, 176, 94, 61, 166, 16, 63, 177, 31, 46, 166, 26, 122, 170, 16, 122, 169, 17, 49, 166, 13, 5, 164, 27, 52, 166, 12, 59, 183, 27, 62, 237, 10, 34, 183, 116, 90};
static unsigned char enc_PASSFILE_ERROR[] = {31, 177, 12, 53, 177, 68, 122, 179, 31, 41, 176, 9, 53, 177, 26, 116, 183, 6, 46, 227, 24, 51, 175, 27, 122, 173, 17, 46, 227, 24, 53, 182, 16, 62, 201, 126};
static unsigned char enc_SERIALFILE_ERROR[] = {31, 177, 12, 53, 177, 94, 57, 177, 27, 59, 183, 23, 52, 164, 94, 41, 166, 12, 51, 162, 18, 116, 183, 6, 46, 227, 24, 51, 175, 27, 90};
static unsigned char enc_KEY[] = {17, 134, 39, 126, 187, 6, 34, 187, 6, 34, 187, 6, 34, 187, 90, 90};
static unsigned char enc_MSG_WRONG_PASS[] = {13, 177, 17, 52, 164, 94, 42, 162, 13, 41, 180, 17, 40, 167, 95, 80, 195};

static const unsigned char xor_key[] = { 0x5A, 0xC3, 0x7E };
static const int xor_key_len = sizeof(xor_key);

// Функции для работы с зашифрованными строками
char* decrypt_string(unsigned char *enc, int enclen) {
    for (int i = 0; i < enclen; ++i) {
        enc[i] ^= xor_key[i % xor_key_len];
    }
    return (char*)enc;
}

void secure_printf(unsigned char* enc_str, int str_len) {
    char* decrypted = decrypt_string(enc_str, str_len);
    printf("%s", decrypted);
    decrypt_string(enc_str, str_len);
}

FILE* secure_fopen(unsigned char* enc_filename, int filename_len, const char* mode) {
    char* filename = decrypt_string(enc_filename, filename_len);
    FILE* file = fopen(filename, mode);
    decrypt_string(enc_filename, filename_len);
    return file;
}

void GenerateJokes() {
    srand((unsigned)time(NULL));

    const char* joke_parts1[] = {
        "Why did the programmer", "Why does the computer", "Why did the code", "How to explain to a bug",
        "Why does the keyboard", "Why did the compiler", "Why does the laptop", "Why did the mouse",
        "Why does the Internet", "Why did the server", "Why does the student coder", "Why did the debugger"
    };
    
    const char* joke_parts2[] = {
        "go to the bar?", "not sleep at night?", "break?", "talk to the toaster?",
        "keep pressing Enter?", "throw an error?", "start overheating?", "run away from the desk?",
        "crash again?", "forget the password?", "freeze in winter?", "argue with the printer?"
    };
    
    const char* joke_parts3[] = {
        "Because he found a bug in the menu!", "To find a memory leak!", "He was looking for a way out of the loop!", 
        "Trying to compile dreams!", "Because someone pressed Ctrl+Alt+Del too hard!", "It couldn't handle the pressure of recursion!", 
        "Searching for Wi-Fi in another dimension!", "It mistook RAM for jam!", "Because the code needed some coffee!", 
        "To hide from infinite loops!", "Because semicolons are scary!", "It was debugging its own life!"
    };

    int size1 = sizeof(joke_parts1) / sizeof(joke_parts1[0]);
    int size2 = sizeof(joke_parts2) / sizeof(joke_parts2[0]);
    int size3 = sizeof(joke_parts3) / sizeof(joke_parts3[0]);

    FILE* joke_file = secure_fopen(enc_JOKESFILE, sizeof(enc_JOKESFILE), "w");
    if (joke_file) {
        char* header = decrypt_string(enc_JOKES_HEADER, sizeof(enc_JOKES_HEADER));
        fprintf(joke_file, "%s", header);
        decrypt_string(enc_JOKES_HEADER, sizeof(enc_JOKES_HEADER));
        
        int jokes_count = 3 + rand() % 3; 
        for (int i = 0; i < jokes_count; i++) {
            int part1 = rand() % size1;
            int part2 = rand() % size2;
            int part3 = rand() % size3;

            fprintf(joke_file, "Joke #%d:\n", i + 1);
            fprintf(joke_file, "- %s %s\n", joke_parts1[part1], joke_parts2[part2]);
            fprintf(joke_file, "- %s\n\n", joke_parts3[part3]);
        }

        fclose(joke_file);
        secure_printf(enc_MSG_JOKES_CREATED, sizeof(enc_MSG_JOKES_CREATED));
    }
}

void ShowSuccessWindow() {
    char* message = decrypt_string(enc_MSG_SUCCESS_1, sizeof(enc_MSG_SUCCESS_1));
    char* title = decrypt_string(enc_MSG_SUCCESS_2, sizeof(enc_MSG_SUCCESS_2));
    
    MessageBoxA(NULL, message, title, MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
    
    decrypt_string(enc_MSG_SUCCESS_1, sizeof(enc_MSG_SUCCESS_1));
    decrypt_string(enc_MSG_SUCCESS_2, sizeof(enc_MSG_SUCCESS_2));
}

void ShowErrorWindow() {
    char* message = decrypt_string(enc_MSG_ERROR_1, sizeof(enc_MSG_ERROR_1));
    char* title = decrypt_string(enc_MSG_ERROR_2, sizeof(enc_MSG_ERROR_2));

    MessageBoxA(NULL, message, title, MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
    
    decrypt_string(enc_MSG_ERROR_1, sizeof(enc_MSG_ERROR_1));
    decrypt_string(enc_MSG_ERROR_2, sizeof(enc_MSG_ERROR_2));
}

#pragma code_seg(".mytext")
NOINLINE int Check_passw(void) {
    FILE* pasw_file = secure_fopen(enc_PASSFILE, sizeof(enc_PASSFILE), "r");
    if (pasw_file == NULL) {
        secure_printf(enc_PASSFILE_ERROR, sizeof(enc_PASSFILE_ERROR));
        return 0;
    }
    
    char* pasw = (char*)calloc(MAX_LEN, sizeof(char));
    fgets(pasw, MAX_LEN, pasw_file);
    fclose(pasw_file);
    
    pasw[strcspn(pasw, "\n")] = 0;
    
    if (strcmp(PASSWORD, pasw) == 0) {
        if (!PasswordCheckSilent()) {
            secure_printf(enc_MSG_WRONG_PASS, sizeof(enc_MSG_WRONG_PASS));
            free(pasw);
            return 0;
        }

        FILE* key_file = secure_fopen(enc_SERIALFILE, sizeof(enc_SERIALFILE), "w");
        if (key_file == NULL) {
            secure_printf(enc_SERIALFILE_ERROR, sizeof(enc_SERIALFILE_ERROR));
            free(pasw);
            return 0;
        }
        
        decrypt_string(enc_KEY, sizeof(enc_KEY));
        srand(time(NULL));
        
        for (int i = 0; i < 10; i++) {
            enc_KEY[4 + i] = 33 + rand() % 94; 
        }
        
        fprintf(key_file, "%s", enc_KEY);
        fclose(key_file);
        
        secure_printf(enc_MSG_SERIAL_CREATED, sizeof(enc_MSG_SERIAL_CREATED));
        printf(": %s\n", enc_KEY);
        decrypt_string(enc_KEY, sizeof(enc_KEY));
        
        free(pasw);
        return 1;
    }
    else {
        secure_printf(enc_MSG_WRONG_PASS, sizeof(enc_MSG_WRONG_PASS));
        free(pasw);
        return 0;
    }
}
NOINLINE void Check_passw_end(void) {
    /* пусто — служебный маркер */
}
#pragma code_seg(pop)
#pragma comment(linker, "/SECTION:.mytext,ERW")

int PasswordCheckSilent(void) {
    FILE* f = secure_fopen(enc_PASSFILE, sizeof(enc_PASSFILE), "r");
    if (!f) return 0;

    char buf[MAX_LEN];
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);
    buf[strcspn(buf, "\r\n")] = 0; // убираем CRLF/NL

    // Сравниваем с эталоном — PASSWORD макрос либо можно сравнить с enc_PASSWORD после дешифровки.
    // Лучше — сравнить с зашифрованной строкой, чтобы не иметь plain‑text в бинарнике.
    // Тут использую decrypt для enc_PASSWORD, копирую в stack и сразу re-encrypt.
    char local_pw[MAX_LEN];
    decrypt_string(enc_PASSWORD, sizeof(enc_PASSWORD));
    strncpy(local_pw, (char*)enc_PASSWORD, sizeof(local_pw)-1);
    decrypt_string(enc_PASSWORD, sizeof(enc_PASSWORD));

    if (strcmp(local_pw, buf) == 0) return 1;
    return 0;
}


int VerifyIntegrity(void) {
    unsigned char *start = (unsigned char*)Check_passw;
    unsigned char *end   = (unsigned char*)Check_passw_end;
    if (end <= start) {
        // какая-то аномалия: возможно оптимизатор / компоновщик поменял порядок
        MessageBoxA(NULL, "Integrity check cannot determine function bounds.", "Error", MB_ICONERROR);
        return 0;
    }
    size_t size = (size_t)(end - start);

    uint32_t crc_now = crc32(start, size);

    const uint32_t crc_expected = 0x0327137F; 
    printf("[DEBUG] CRC of Check_passw: %08X\n", crc_now);
    if (crc_now != crc_expected) {
        MessageBoxA(NULL, "Integrity check failed!", "Tamper", MB_ICONERROR);
        return 0;
    }
    return 1;
}


int main() {
    if (!VerifyIntegrity()) {
        return 1;
    }

    if (!PasswordCheckSilent()) {
        // можно вывести уведомление (шифрованное) и выйти
        MessageBoxA(NULL, "Password check failed (early).", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    secure_printf(enc_MSG_START, sizeof(enc_MSG_START));
    secure_printf(enc_MSG_READ, sizeof(enc_MSG_READ));

    if ( Check_passw()){
        ShowSuccessWindow();
        if (PasswordCheckSilent()) {
            GenerateJokes();
        } else {
            MessageBoxA(NULL, "Password check failed (pre-jokes).", "Error", MB_OK | MB_ICONERROR);
        }
    } else{
        ShowErrorWindow();
    }
    
    secure_printf(enc_MSG_COMPLETE, sizeof(enc_MSG_COMPLETE));
    printf("Press Enter to exit...\n");
    getchar();
    
    return 0;
}