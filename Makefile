CXX=g++
CXXFLAGS=-Wall -Wextra -std=c++17

TARGET=mfw
SRC=main.cpp

all:
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)
