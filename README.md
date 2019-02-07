# 🦈WDissectorGen🦈 - Wireshark Dissectors Generator
## Intruduction
WDissectorGen writes for you LUA code to implements a Wireshark Dissectors. You only need describe your protocol in yaml format!

## Installation & Usage
- ``` pip install -r requirements.txt``` to install software dependency
- ``` python wdissectorgen.py schema.yaml <protocol_name>.yaml``` to generate the Wireshark Dissector
- For Debian based distribution use```cp <protocol_name>.lua $HOME/.local/bin/wireshark/plugins``` to copy the LUA script in the plugin wireshark folder
- Press ```CTRL+SHIFT+L``` in Wireshark to reload the LUA script engine

## Example
See inside the ```example``` folder to study a simple usage example.