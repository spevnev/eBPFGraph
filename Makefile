CC      := gcc
CFLAGS  := -O2 -std=c17 -Wall -Wextra -pedantic -Isrc -MMD -MP
LDFLAGS := $(shell pkg-config --libs raylib)

ifeq ($(DEBUG), 1)
	CFLAGS += -g3 -fstack-protector -fsanitize=address,leak,undefined -DDEBUG
endif

BIN_NAME := graph

SOURCE_DIR  := src
BUILD_DIR   := build
OBJECTS_DIR := $(BUILD_DIR)/$(SOURCE_DIR)

SOURCES := $(shell find $(SOURCE_DIR) -type f -name '*.c')
OBJECTS := $(patsubst $(SOURCE_DIR)/%.c, $(OBJECTS_DIR)/%.o, $(SOURCES))
BINARY  := $(BUILD_DIR)/$(BIN_NAME)

OBJECTS      := $(patsubst $(SOURCE_DIR)/%.c, $(OBJECTS_DIR)/%.o, $(SOURCES))
DEPENDENCIES := $(patsubst %.o, %.d, $(OBJECTS))

.PHONY: all
all: build

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

.PHONY: build
build: $(BINARY)

$(BINARY): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJECTS_DIR)/%.o: $(SOURCE_DIR)/%.c Makefile
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ -c $<

-include $(DEPENDENCIES)
