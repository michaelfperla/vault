ASM = nasm
LD = ld
ASMFLAGS = -f elf64
LDFLAGS = -s

TARGET = vault
SRC = vault.asm
OBJ = vault.o

all: $(TARGET)

$(TARGET): $(OBJ)
	$(LD) $(LDFLAGS) -o $@ $<

$(OBJ): $(SRC)
	$(ASM) $(ASMFLAGS) -o $@ $<

clean:
	rm -f $(OBJ) $(TARGET)

install: $(TARGET)
	cp $(TARGET) $(HOME)/.local/bin/$(TARGET)

.PHONY: all clean install
