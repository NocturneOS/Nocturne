set -e

echo '+ Compiling Debug'
cmake --build cmake-build-debug/ -j4 -- iso
echo '+ Compiling Release'
cmake --build cmake-build-release/ -j4 -- iso
echo '+ Compiling ReleaseOpt'
cmake --build cmake-build-release-opt/ -j4 -- iso
