# securexfer build configuration

CC       ?= cc
CSTD      = -std=c11
WARNINGS  = -Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion -Wstrict-prototypes
INCLUDES  = -Iinclude
CFLAGS    = $(CSTD) $(WARNINGS) $(INCLUDES)
LDLIBS    = -lcrypto

# Sanitizers for the debug/test builds: catch memory and UB errors early.
SANITIZE  = -fsanitize=address,undefined -fno-omit-frame-pointer -g

BUILD     = build
SRC       = $(wildcard src/*.c)
OBJ       = $(patsubst src/%.c,$(BUILD)/%.o,$(SRC))

LIB       = $(BUILD)/libsecurexfer.a
BIN       = $(BUILD)/securexfer

TEST_SRC  = $(wildcard tests/*.c)
TEST_BIN  = $(patsubst tests/%.c,$(BUILD)/%,$(TEST_SRC))

.PHONY: all release debug test clean run

all: release

# Release: optimized, strict, no sanitizers.
release: CFLAGS += -O2 -DNDEBUG
release: $(BIN)

# Debug: sanitizers on, for development.
debug: CFLAGS += $(SANITIZE) -O0
debug: LDLIBS += -fsanitize=address,undefined
debug: $(BIN)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB): $(OBJ)
	ar rcs $@ $^

$(BIN): app/main.c $(LIB) | $(BUILD)
	$(CC) $(CFLAGS) app/main.c $(LIB) $(LDLIBS) -o $@

# Tests are built and run with sanitizers enabled.
test: CFLAGS += $(SANITIZE) -O0
test: $(LIB) $(TEST_BIN)
	@echo "Running tests..."
	@for t in $(TEST_BIN); do echo "== $$t =="; ./$$t || exit 1; done
	@echo "All tests passed."

$(BUILD)/%: tests/%.c $(LIB) | $(BUILD)
	$(CC) $(CFLAGS) $(SANITIZE) $< $(LIB) $(LDLIBS) -fsanitize=address,undefined -o $@

run: release
	./$(BIN) --help

clean:
	rm -rf $(BUILD)
