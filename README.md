## Dependencies
- python3
- python3-graph-tool
- radare2 + python3 bindings
- unicorn + python3 bindings
- graphviz + python3 bindings

Ubuntu 18.04 installation:
[graph-tool installation instructions](https://git.skewed.de/count0/graph-tool/wikis/installation-instructions#debian-ubuntu)
```
sudo apt install python3 radare2
pip3 install unicorn
pip3 install r2pipe
sudo apt install python3-gv
```

## Usage
### Command template
```
./undo_flattening.py path_to_binary hex_start_address_of_function [state_register_name]
```
### Single example
```
./undo_flattening.py samples/fla_test.elf 0x000400500
```
### All samples from ./samples
```
./run_samples.sh
```

Patched binaries will be created at path_to_binary.patched


## Limitations
- x86-64 only right now. Should be easy to change emulation code to support x86
