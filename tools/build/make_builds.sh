set -e

cmake -B cmake-build-debug -G Ninja . -DCMAKE_BUILD_TYPE=Debug
cmake -B cmake-build-release -G Ninja . -DCMAKE_BUILD_TYPE=Release
cmake -B cmake-build-release-opt -G Ninja . -DCMAKE_BUILD_TYPE=ReleaseOptimized

cmake -B cmake-build-debug64 -G Ninja . -DCMAKE_BUILD_TYPE=Debug -DNOCTURNE_ARCH=x86_64
cmake -B cmake-build-release64 -G Ninja . -DCMAKE_BUILD_TYPE=Release -DNOCTURNE_ARCH=x86_64
cmake -B cmake-build-release-opt64 -G Ninja . -DCMAKE_BUILD_TYPE=ReleaseOptimized -DNOCTURNE_ARCH=x86_64

