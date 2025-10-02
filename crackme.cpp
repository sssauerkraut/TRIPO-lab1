#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>

#define PASSWORD "september2025"
#define MAX_LEN 50
#define KEY_LEN 10

void GenerateJokes() {
    srand((unsigned)time(NULL));

    const char* joke_parts1[] = {
        "Why did the programmer", 
        "Why does the computer", 
        "Why did the code", 
        "How to explain to a bug",
        "Why does the keyboard", 
        "Why did the compiler", 
        "Why does the laptop", 
        "Why did the mouse",
        "Why does the Internet", 
        "Why did the server",
        "Why does the student coder",
        "Why did the debugger"
    };
    
    const char* joke_parts2[] = {
        "go to the bar?", 
        "not sleep at night?", 
        "break?", 
        "talk to the toaster?",
        "keep pressing Enter?", 
        "throw an error?", 
        "start overheating?", 
        "run away from the desk?",
        "crash again?", 
        "forget the password?",
        "freeze in winter?",
        "argue with the printer?"
    };
    
    const char* joke_parts3[] = {
        "Because he found a bug in the menu!", 
        "To find a memory leak!", 
        "He was looking for a way out of the loop!", 
        "Trying to compile dreams!",
        "Because someone pressed Ctrl+Alt+Del too hard!", 
        "It couldn’t handle the pressure of recursion!", 
        "Searching for Wi-Fi in another dimension!", 
        "It mistook RAM for jam!",
        "Because the code needed some coffee!", 
        "To hide from infinite loops!",
        "Because semicolons are scary!",
        "It was debugging its own life!"
    };

    int size1 = sizeof(joke_parts1) / sizeof(joke_parts1[0]);
    int size2 = sizeof(joke_parts2) / sizeof(joke_parts2[0]);
    int size3 = sizeof(joke_parts3) / sizeof(joke_parts3[0]);

    FILE* joke_file = fopen("jokes_generated.txt", "w");
    if (joke_file) {
        fprintf(joke_file, "SOME JOKES\n\n");

        int jokes_count = 3 + rand() % 3; 
        for (int i = 0; i < jokes_count; i++) {
            int part1 = rand() % size1;
            int part2 = rand() % size2;
            int part3 = rand() % size3;

            while (part2 == part1) part2 = rand() % size2;
            while (part3 == part2 || part3 == part1) part3 = rand() % size3;

            fprintf(joke_file, "Joke #%d:\n", i + 1);
            fprintf(joke_file, "- %s %s\n", joke_parts1[part1], joke_parts2[part2]);
            fprintf(joke_file, "- %s\n\n", joke_parts3[part3]);
        }

        fclose(joke_file);
        printf("Additional: jokes generated in jokes_generated.txt\n");
    }
}


void ShowSuccessWindow() {
    MessageBoxA(
        NULL,
        "Password correct!\n\n"
        "Serial number generated and saved in serial.txt file",
        "Success",
        MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL
    );
}

void ShowErrorWindow() {
    MessageBoxA(
        NULL,
        "Wrong password!\n\n"
        "Check password.txt file and try again.",
        "Error",
        MB_OK | MB_ICONERROR | MB_SYSTEMMODAL
    );
}

int Check_passw(void) {
    FILE* pasw_file = fopen("password.txt", "r");
    if (pasw_file == NULL) {
        printf("Error: password.txt file not found\n");
        return 0;
    }
    
    char* pasw = (char*)calloc(MAX_LEN, sizeof(char));
    fgets(pasw, MAX_LEN, pasw_file);
    fclose(pasw_file);
    
    pasw[strcspn(pasw, "\n")] = 0;
    
    if (strcmp(PASSWORD, pasw) == 0) {
        FILE* key_file = fopen("serial.txt", "w");
        if (key_file == NULL) {
            printf("Error creating serial.txt file\n");
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
        printf("Serial number created: %s\n", key);
        
        free(pasw);
        return 1;
    }
    else {
        printf("Wrong password!\n");
        free(pasw);
        return 0;
    }
}

int main() {
    printf("Starting password check program...\n");
    printf("Reading password from password.txt file...\n");
    
    if (Check_passw()) {
        ShowSuccessWindow();
        
        GenerateJokes();
    }
    else {
        ShowErrorWindow();
    }
    
    printf("Program completed. Press Enter to exit...\n");
    getchar();
    
    return 0;
}