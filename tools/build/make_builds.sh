set -e

cmake -B cmake-build-debug -G Ninja . -DCMAKE_BUILD_TYPE=Debug
cmake -B cmake-build-release -G Ninja . -DCMAKE_BUILD_TYPE=Release
cmake -B cmake-build-release-opt -G Ninja . -DCMAKE_BUILD_TYPE=ReleaseOptimized
#cmake -B cmake-build-release-opt-sse -G Ninja . -DCMAKE_BUILD_TYPE=ReleaseOptimizedSSE

