CXX      = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -I include
BUILD    = build
SRC      = $(wildcard src/*.cpp)

server: $(BUILD)/server_main.o $(BUILD)/server.o $(BUILD)/protocol.o
	$(CXX) $^ -o $@

client: $(BUILD)/client_main.o $(BUILD)/client.o $(BUILD)/protocol.o
	$(CXX) $^ -o $@

$(BUILD)/%.o: src/%.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD):
	mkdir -p $@

clean:
	rm -rf build client server

.PHONY: clean all
