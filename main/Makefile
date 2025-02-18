# 设置编译器
CXX = g++
CXXFLAGS = -std=c++20 -g -Wunused-function
INCLUDES = -I. -I..
#LDFLAGS = -L..
LIBS = -lpthread
#RPATH = -Wl,-rpath -Wl,..

# 源文件和对象文件定义
SRC = main.cc
SRC += ../tc_http/tc_clientsocket.cc ../tc_http/tc_common.cc ../tc_http/tc_ex.cc ../tc_http/tc_http.cc ../tc_http/tc_socket.cc ../tc_http/tc_epoller.cc
OBJ = $(SRC:.cc=.o)

# 最终目标文件
TARGET = test

# 默认目标
all: $(TARGET)

# 链接阶段
$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS) $(RPATH)

# 编译阶段
%.o: %.cc
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

# 清理目标文件
clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean