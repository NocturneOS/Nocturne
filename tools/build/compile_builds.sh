set -e

echo '+ Compiling Debug'
cmake --build cmake-build-debug/ -j$(nproc) -- iso
echo '+ Compiling Release'
cmake --build cmake-build-release/ -j$(nproc) -- iso
echo '+ Compiling ReleaseOpt'
cmake --build cmake-build-release-opt/ -j$(nproc) -- iso

echo '+ [x64] Compiling Debug'
cmake --build cmake-build-debug64/ -j$(nproc) -- iso
echo '+ [x64] Compiling Release'
cmake --build cmake-build-release64/ -j$(nproc) -- iso
echo '+ [x64] Compiling ReleaseOpt'
cmake --build cmake-build-release-opt64/ -j$(nproc) -- iso
