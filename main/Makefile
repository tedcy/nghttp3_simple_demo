# 设置编译器
CXX = g++
CXXFLAGS = -fPIC -std=c++20 -g -O2 -Wunused-function
INCLUDES = -I. -I..
LIBS = -lpthread

# 源文件和对象文件定义
SRC = main.cc
SRC += ../tc_http/tc_clientsocket.cc ../tc_http/tc_common.cc ../tc_http/tc_ex.cc ../tc_http/tc_http.cc ../tc_http/tc_socket.cc ../tc_http/tc_epoller.cc
# .o 文件名与当前目录下的目标文件一致
OBJ = $(notdir $(SRC:.cc=.o))

# 最终目标文件
TARGET = test

# 默认目标
all: $(TARGET)

# 链接阶段
$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

# 编译阶段
%.o: ../tc_http/%.cc
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

main.o: main.cc
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

# 清理目标文件
clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean