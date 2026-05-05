ОПИСАНИЕ: приложение с End-To-End криптиране. От Васил Тодоров.

КОМПИЛИРАНЕ: make; gcc test_crypto.c crypto.c -o test_crypto -lssl -lcrypto(за тестоше)
СТАРТИРАНЕ: terminal1: ./server; terminal2: ./client; terminal3: ./client
ТЕСТВАНЕ: ./test_crypto

СТРУКТУРА: 
typedef struct {
    int type;
    int length;
    unsigned char data[BUFFER_SIZE];
} packet_t;
публичен ключ=2, сесиен ключ=3, съобщение=4. data съдържа 12 байта IV + 16 байта GCM Tag + Ciphertext
ТРУДНОСТИ: работа със сървъра