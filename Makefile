CC = gcc
CFLAGS = -O3 -pthread -march=native -mtune=native -flto -pipe
LIBS = -lpthread -lm
TARGET = ddos

all: $(TARGET)

$(TARGET): ddos_engine.c
	$(CC) $(CFLAGS) -o $(TARGET) ddos_engine.c $(LIBS)
	strip $(TARGET)
	@echo "[✓] Build complete: ./$(TARGET)"

static:
	$(CC) $(CFLAGS) -static -o $(TARGET)-static ddos_engine.c $(LIBS)
	strip $(TARGET)-static
	@echo "[✓] Static build: ./$(TARGET)-static"

install:
	cp $(TARGET) /usr/local/bin/
	@echo "[✓] Installed to /usr/local/bin/$(TARGET)"

clean:
	rm -f $(TARGET) $(TARGET)-static

.PHONY: all static install clean
