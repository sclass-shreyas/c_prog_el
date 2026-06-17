#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_KEYWORDS 200
#define MAX_KEYWORD_LEN 64
#define MAX_LINE_LEN 256
#define INPUT_CHUNK 1024
#define INITIAL_INPUT_CAPACITY 4096
#define SPAM_THRESHOLD 50

typedef struct {
    char word[MAX_KEYWORD_LEN];
    int weight;
} SpamKeyword;

static void trim_newline(char *text) {
    size_t len = strlen(text);
    while (len > 0 && (text[len - 1] == '\n' || text[len - 1] == '\r')) {
        text[len - 1] = '\0';
        len--;
    }
}

static void to_lowercase(char *text) {
    for (size_t i = 0; text[i] != '\0'; i++) {
        text[i] = (char)tolower((unsigned char)text[i]);
    }
}

static int load_keywords(const char *file_path, SpamKeyword keywords[], int max_keywords) {
    FILE *file = fopen(file_path, "r");
    if (file == NULL) {
        fprintf(stderr, "ERROR: Could not open keyword file: %s\n", file_path);
        return -1;
    }

    int count = 0;
    char line[MAX_LINE_LEN];

    while (fgets(line, sizeof(line), file) != NULL) {
        if (count >= max_keywords) {
            fprintf(stderr, "WARNING: Maximum keyword limit reached (%d).\n", max_keywords);
            break;
        }

        trim_newline(line);

        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        char keyword[MAX_KEYWORD_LEN];
        int weight = 0;

        if (sscanf(line, "%63[^,],%d", keyword, &weight) == 2) {
            to_lowercase(keyword);
            strncpy(keywords[count].word, keyword, MAX_KEYWORD_LEN - 1);
            keywords[count].word[MAX_KEYWORD_LEN - 1] = '\0';
            keywords[count].weight = weight;
            count++;
        }
    }

    fclose(file);
    return count;
}

static char *read_stdin_text(void) {
    size_t capacity = INITIAL_INPUT_CAPACITY;
    size_t length = 0;
    char *buffer = (char *)malloc(capacity);
    if (buffer == NULL) {
        fprintf(stderr, "ERROR: Memory allocation failed.\n");
        return NULL;
    }

    buffer[0] = '\0';

    char chunk[INPUT_CHUNK];
    while (fgets(chunk, sizeof(chunk), stdin) != NULL) {
        size_t chunk_len = strlen(chunk);
        if (length + chunk_len + 1 > capacity) {
            while (length + chunk_len + 1 > capacity) {
                capacity *= 2;
            }
            char *new_buffer = (char *)realloc(buffer, capacity);
            if (new_buffer == NULL) {
                free(buffer);
                fprintf(stderr, "ERROR: Memory reallocation failed.\n");
                return NULL;
            }
            buffer = new_buffer;
        }

        memcpy(buffer + length, chunk, chunk_len);
        length += chunk_len;
        buffer[length] = '\0';
    }

    return buffer;
}

static int calculate_spam_score(const char *email_text, const SpamKeyword keywords[], int keyword_count) {
    int total_score = 0;

    for (int i = 0; i < keyword_count; i++) {
        if (strstr(email_text, keywords[i].word) != NULL) {
            total_score += keywords[i].weight;
        }
    }

    return total_score;
}

int main(void) {
    SpamKeyword keywords[MAX_KEYWORDS];
    int keyword_count = load_keywords("spam_keywords.txt", keywords, MAX_KEYWORDS);
    if (keyword_count < 0) {
        return 1;
    }

    char *email_text = read_stdin_text();
    if (email_text == NULL) {
        return 1;
    }

    to_lowercase(email_text);
    int spam_score = calculate_spam_score(email_text, keywords, keyword_count);
    const char *classification = (spam_score > SPAM_THRESHOLD) ? "SPAM" : "SAFE";

    /*
     * Keep output machine-friendly for easy parsing from Python.
     */
    printf("CLASSIFICATION=%s\n", classification);
    printf("SPAM_SCORE=%d\n", spam_score);

    free(email_text);
    return 0;
}
