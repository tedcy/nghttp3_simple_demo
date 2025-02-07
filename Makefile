# 设置编译器
CXX = g++
CXXFLAGS = -std=c++20 -DHAVE_CONFIG_H -DWITH_EXAMPLE_BORINGSSL -g -O2 -Wunused-function
INCLUDES = -I. -I/root/http3/ngtcp2 -I/root/http3/ngtcp2/lib/includes -I/root/http3/ngtcp2/crypto/includes -I/root/http3/ngtcp2/third-party \
           -I/root/http3/ngtcp2/../libev/build/include \
           -I/root/http3/nghttp3/build/include \
           -I/root/http3/ngtcp2/../boringssl/build \
           -I/root/http3/ngtcp2/../boringssl/include
LDFLAGS = -L/root/http3/ngtcp2/../libev/build/lib \
          -L/root/http3/nghttp3/build/lib \
          -L/root/http3/ngtcp2/../boringssl/build/ssl \
          -L/root/http3/ngtcp2/../boringssl/build/crypto
LIBS = /root/http3/ngtcp2/lib/.libs/libngtcp2.so /root/http3/ngtcp2/third-party/.libs/libhttp-parser.a \
       /root/http3/libev/build/lib/libev.so /root/http3/nghttp3/build/lib/libnghttp3.so \
       /root/http3/ngtcp2/crypto/boringssl/libngtcp2_crypto_boringssl.a -lssl -lcrypto -lpthread
RPATH = -Wl,-rpath -Wl,/root/http3/ngtcp2/lib/.libs \
        -Wl,-rpath -Wl,/root/http3/libev/build/lib \
        -Wl,-rpath -Wl,/root/http3/nghttp3/build/lib

# 源文件和对象文件定义
SRC = client.cc client_base.cc debug.cc util.cc shared.cc \
      tls_client_context_boringssl.cc tls_client_session_boringssl.cc \
      tls_session_base_openssl.cc util_openssl.cc
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