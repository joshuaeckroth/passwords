#git clone https://github.com/majensen/libneo4j-client.git libneo4j-client-v4
#mkdir libneo4j-client-v4-install
#cd libneo4j-client-v4
#./autogen.sh
#export LDFLAGS="-L/opt/homebrew/opt/openssl@1.1/lib"
#export CPPFLAGS="-I/opt/homebrew/opt/openssl@1.1/include"
#export PKG_CONFIG_PATH="/opt/homebrew/opt/openssl@1.1/lib/pkgconfig"
#./configure --prefix=`pwd`/../libneo4j-client-v4-install --disable-tools --disable-werror
#make install
#cd ..
git clone git@github.com:hashcat/hashcat.git
cd hashcat && make obj/combined.NATIVE.a
git clone https://github.com/antirez/rax.git
