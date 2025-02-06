## build nghttp3

```
mkdir http3
cd http3
```

and then

```
wget https://github.com/Kitware/CMake/releases/download/v3.31.4/cmake-3.31.4-linux-x86_64.tar.gz
tar xf cmake-3.31.4-linux-x86_64.tar.gz

wget https://studygolang.com/dl/golang/go1.23.5.linux-amd64.tar.gz
tar xf go1.23.5.linux-amd64.tar.gz
export GOROOT=/root/go
export GOPATH=/root/gopath
export PATH=$PATH:$GOPATH/bin:$GOROOT/bin

git clone https://boringssl.googlesource.com/boringssl
cd boringssl
git checkout b0b1f9dfc583c96d5f91b7f8cdb7efabcf22793b
../cmake-3.31.4-linux-x86_64/bin/cmake -B build -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_CXX_FLAGS="-Wno-error=format"
make -j$(nproc) -C build
cd ..

git clone https://github.com/ngtcp2/nghttp3
cd nghttp3
git checkout v0.15.0
git submodule update --init --recursive
autoreconf -i
./configure --prefix=$PWD/build --enable-lib-only
make -j$(nproc) check
make install
cd ..

git clone https://github.com/enki/libev
cd libev
git submodule update --init --recursive
autoreconf -i
./configure --prefix=$PWD/build
make -j$(nproc) check
make install
cd ..

git clone https://github.com/ngtcp2/ngtcp2
cd ngtcp2
git checkout v0.15.0
git submodule update --init --recursive
autoreconf -i
./configure PKG_CONFIG_PATH=$PWD/../nghttp3/build/lib/pkgconfig     BORINGSSL_LIBS="-L$PWD/../boringssl/build/ssl -lssl -L$PWD/../boringssl/build/crypto -lcrypto -lpthread"     BORINGSSL_CFLAGS="-I$PWD/../boringssl/build -I$PWD/../boringssl/include"  --with-boringssl --with-openssl=no LIBEV_LIBS="-L$PWD/../libev/build/lib -lev" LIBEV_CFLAGS="-I$PWD/../libev/build/include" --with-libev
make -j$(nproc) check
```

## build demo

```
git clone https://github.com/tedcy/nghttp3_simple_demo.git
make -j
```

## run demo

```
./go_server/run.sh
```

open another shell

```
./test localhost 4433 https://localhost/
```