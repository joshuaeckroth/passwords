git clone https://github.com/majensen/libneo4j-client.git libneo4j-client-v4
mkdir libneo4j-client-v4-install
cd libneo4j-client-v4
./autogen.sh
export LDFLAGS="-L/opt/homebrew/opt/openssl@1.1/lib"
export CPPFLAGS="-I/opt/homebrew/opt/openssl@1.1/include"
export PKG_CONFIG_PATH="/opt/homebrew/opt/openssl@1.1/lib/pkgconfig"
./configure --prefix=`pwd`/../libneo4j-client-v4-install --disable-tools --disable-werror
make install
cd ..
git clone git@github.com:hashcat/hashcat.git
cd hashcat && make obj/combined.NATIVE.a
wget -c "https://boostorg.jfrog.io/artifactory/main/release/1.80.0/source/boost_1_80_0.tar.bz2"
tar --bzip2 -xf boost_1_80_0.tar.bz2
