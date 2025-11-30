CXX      = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -I include
BUILD    = build
SRC      = $(wildcard src/*.cpp)

all: server client

server: $(BUILD)/server_main.o $(BUILD)/database.o $(BUILD)/server.o $(BUILD)/bcrypt.o $(BUILD)/protocol.o
	$(CXX) $^ -o $@ -lsqlite3 -lbcrypt

client: $(BUILD)/client_main.o $(BUILD)/bcrypt.o $(BUILD)/client.o $(BUILD)/protocol.o
	$(CXX) $^ -o $@ -lbcrypt

$(BUILD)/%.o: src/%.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD):
	mkdir -p $@

clean:
	rm -rf build client server

.PHONY: clean all
