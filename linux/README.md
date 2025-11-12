# tcp_state_analyzer (linux folder)

This folder contains the tcp_state_analyzer tool copied for uploading to a GitHub repository under a `linux/` project.

Files:
- `tcp_state_analyzer.c` — wrapper that includes the root source file.
- `CMakeLists.txt` — simple CMake file that builds the binary if libpcap is available.

Build (Linux):

```bash
sudo apt update
sudo apt install build-essential libpcap-dev cmake
mkdir build && cd build
cmake ..
make -j
```

Run (requires privileges):

```bash
sudo ./tcp_state_analyzer -i <interface> [-o out.dot]
```

Note: The canonical source is located at the repository root; this file simply provides a linux/ project layout for GitHub.
