# generate_enc.py
key = bytes([0x5A, 0xC3, 0x7E])   # используемый XOR-ключ (можно заменить)
def enc_bytes(s):
    b = s.encode('utf-8') + b'\x00'   # включаем нуль-терминатор
    out = [(b[i] ^ key[i % len(key)]) for i in range(len(b))]
    return out

strings = {
    'PASSWORD': 'september2025',
    'PASSFILE': 'password.txt',
    'SERIALFILE': 'serial.txt',
    'JOKESFILE': 'jokes_generated.txt',
    'JOKES_HEADER': 'SOME JOKES\n\n',
    'MSG_SUCCESS_1': 'Password correct!\n\nSerial number generated and saved in serial.txt file',
    'MSG_SUCCESS_2': 'Success',
    'MSG_ERROR_1': 'Wrong password!\n\nCheck password.txt file and try again.',
    'MSG_ERROR_2': 'Error',
    'MSG_START': 'Starting password check program...\n',
    'MSG_READ': 'Reading password from password.txt file...\n',
    'MSG_COMPLETE': 'Program completed. Press Enter to exit...\n',
    'MSG_SERIAL_CREATED': 'Serial number created: ',
    'MSG_JOKES_CREATED': 'Additional: jokes generated in jokes_generated.txt\n',
    'PASSFILE_ERROR': 'Error: password.txt file not found\n',
    'SERIALFILE_ERROR': 'Error creating serial.txt file',
    'KEY': 'KEY$xxxxxxxxxx$',
    'MSG_WRONG_PASS': 'Wrong password!\n',


}

# add jokes arrays as needed
j1 = ["Why did the programmer", "Why does the computer", "Why did the code", ...]  # и т.д.

# generate arrays
for name, s in strings.items():
    e = enc_bytes(s)
    print("static unsigned char enc_%s[] = {%s}; // len %d" % (name, ", ".join(str(x) for x in e), len(e)))
    print("\n");

# для массивов jokes делай аналогично: для каждого элемента с именем enc_J1_0, enc_J1_1, ...
