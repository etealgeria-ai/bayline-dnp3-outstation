#!/usr/bin/env bash
# Builds opendnp3 2.1.0-RC5 (the last release with its SAv5 module) and the scripted test master.
# Needs git, cmake, g++, and the OpenSSL headers. Everything lands in tools/opendnp3-master/build.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="$here/build"
mkdir -p "$work"
cd "$work"
[ -d opendnp3 ] || git clone -q --depth 1 --branch 2.1.0-RC5 https://github.com/dnp3/opendnp3.git opendnp3
[ -d asio ] || git clone -q --depth 1 --branch asio-1-10-6 https://github.com/chriskohlhoff/asio.git asio

# 2015 sources on a current toolchain: OpenSSL 3 hides HMAC_CTX and the locking callbacks,
# and GCC 13 no longer pulls in <functional> and friends transitively.
python3 - "$work/opendnp3" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
hmac = root / "cpp/libs/src/osslcrypto/GenericHMAC.cpp"
text = hmac.read_text()
if "HMAC_CTX_new" not in text:
    text = text.replace("\tHMAC_CTX ctx;\n\tHMAC_CTX_init(&ctx);", "\tHMAC_CTX* pctx = HMAC_CTX_new();")
    text = text.replace("HMAC_CTX_cleanup(&ctx);", "HMAC_CTX_free(pctx);").replace("&ctx", "pctx")
    hmac.write_text(text)
provider = root / "cpp/libs/src/osslcrypto/CryptoProvider.cpp"
text = provider.read_text()
text = text.replace("i < CRYPTO_num_locks()", "i < 0").replace("CRYPTO_set_locking_callback(LockingFunction);", "").replace("mode & CRYPTO_LOCK", "mode & 1")
provider.write_text(text)
cmake = root / "CMakeLists.txt"
text = cmake.read_text()
text = text.replace('set(CMAKE_CXX_FLAGS "-Wall -std=c++11")', 'set(CMAKE_CXX_FLAGS "-std=c++14 -w -fpermissive -include functional -include cstdint -include memory -include string -include vector -include cstring -include limits -include algorithm -include mutex -include thread")')
cmake.write_text(text)
PY

mkdir -p opendnp3/build
(cd opendnp3/build && cmake .. -DSECAUTH=ON -DASIO_HOME="$work/asio/asio/include" > /dev/null && make -j"$(nproc)" > /dev/null)

g++ -std=c++14 -w -fpermissive -include functional -include cstdint -include memory -include string -include vector -include cstring -include mutex -include thread \
    -DASIO_STANDALONE -DOPENDNP3_USE_SECAUTH -DASIO_HAS_STD_SYSTEM_ERROR \
    -I"$work/opendnp3/cpp/libs/include" -I"$work/opendnp3/cpp/libs/src" -I"$work/asio/asio/include" \
    "$here/main.cpp" -o "$work/satest" \
    -L"$work/opendnp3/build" -lasiodnp3 -lsecauth -lasiopal -lopendnp3 -losslcrypto -lopenpal -lssl -lcrypto -lpthread \
    -Wl,-rpath,"$work/opendnp3/build"
echo "built $work/satest"
