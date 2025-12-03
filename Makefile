CXX      = g++
CXXFLAGS = -Wall -Wextra -Werror -std=c++17 -I include
BUILD    = build
SRC      = $(wildcard src/*.cpp)

all: server client

server: $(BUILD)/server_main.o $(BUILD)/database.o $(BUILD)/server.o $(BUILD)/protocol.o $(BUILD)/crypto.o $(BUILD)/net.o $(BUILD)/logger.o
	$(CXX) $^ -o $@ -lsqlite3 -lbcrypt -lcrypto

client: $(BUILD)/client_main.o $(BUILD)/crypto.o $(BUILD)/client.o $(BUILD)/protocol.o $(BUILD)/net.o $(BUILD)/logger.o
	$(CXX) $^ -o $@ -lbcrypt -lcrypto

$(BUILD)/%.o: src/%.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@


$(BUILD):
	mkdir -p $@

clean:
	rm -rf build client server

.PHONY: clean all

# Code quality helpers
FORMATTER ?= clang-format
TIDY ?= clang-tidy

# Format all source and header files in-place
format:
	$(FORMATTER) -i $(SRC) include/*.hpp

# Lint sources with clang-tidy using compile_commands.json.
# Run 'bear -- make' first to generate compile_commands.json if missing.
lint:
	bear -- make clean && bear -- make
	@if [ ! -f compile_commands.json ]; then \
		echo "Error: compile_commands.json not found. Run 'bear -- make' first."; \
		exit 1; \
	fi
	@for f in $(SRC); do \
		$(TIDY) $$f --quiet -p=. ; \
	done

.PHONY: format lint
