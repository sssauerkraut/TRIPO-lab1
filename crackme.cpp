#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>

#define PASSWORD "september2025"
#define MAX_LEN 50
#define KEY_LEN 10

void ShowSuccessWindow() {
    MessageBoxW(
        NULL,
        L"Вы успешно вошли в защищаемое ПО!\n\n"
        L"Серийный ключ был сгенерирован и сохранён в файле serial.txt",
        L"Доступ разрешён!",
        MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL
    );
}

void ShowErrorWindow() {
    MessageBoxW(
        NULL,
        L"Неверный пароль!\n\n"
        L"Проверьте файл password.txt и попробуйте снова.",
        L"Доступ запрещён",
        MB_OK | MB_ICONERROR | MB_SYSTEMMODAL
    );
}

int Check_passw(void) {
    FILE* pasw_file = fopen("password.txt", "r");
    if (pasw_file == NULL) {
        printf("Error ->> password.txt\n");
        return 0;
    }
    
    char* pasw = (char*)calloc(MAX_LEN, sizeof(char));
    fgets(pasw, MAX_LEN, pasw_file);
    fclose(pasw_file);
    
    // Убираем символ новой строки если есть
    pasw[strcspn(pasw, "\n")] = 0;
    
    if (strcmp(PASSWORD, pasw) == 0) {
        FILE* key_file = fopen("serial.txt", "w");
        if (key_file == NULL) {
            printf("Error ->> serial.txt\n");
            free(pasw);
            return 0;
        }
        
        char key[] = "KEY$xxxxxxxxxx$";
        srand(time(NULL));
        
        for (int i = 0; i < 10; i++) {
            key[4 + i] = 33 + rand() % 94;
        }
        
        fprintf(key_file, "%s", key);
        fclose(key_file);
        printf("Serial key created!\n");
        
        free(pasw);
        return 1;
    }
    else {
        free(pasw);
        return 0;
    }
}

int main() {
    
    printf("Starting up...\n");
    
    if (Check_passw()) {
        ShowSuccessWindow();
    }
    else {
        ShowErrorWindow();
    }
    
    return 0;
}