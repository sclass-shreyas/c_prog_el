CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = spam_detector.exe
SOURCE = spam_detector.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET)

clean:
	rm -f $(TARGET)
