# ROP Generator - Advanced Exploitation Framework

## Installation Requirements

```bash
pip install capstone pefile pyelftools z3-solver pycryptodome
```

## Usage Examples

### Basic gadget discovery:
```bash
python rop_generator.py vulnerable_binary.exe
```

### Find specific gadgets:
```bash
python rop_generator.py vulnerable_binary.exe --find "pop rdi"
python rop_generator.py vulnerable_binary.exe --find "syscall"
python rop_generator.py vulnerable_binary.exe --find "mov.*rax"
```

### Export gadgets:
```bash
python rop_generator.py vulnerable_binary.exe -o gadgets.json -f json
python rop_generator.py vulnerable_binary.exe -o gadgets.txt -f txt
```

### Generate ROP chain from specification:
```bash
python rop_generator.py vulnerable_binary.exe --chain example_chain.json
```

## Advanced Features

- **Multi-architecture support**: x86, x64
- **Bad character filtering**: Automatically excludes null bytes, newlines
- **Pattern matching**: Regex-based gadget search
- **Chain generation**: Automated ROP chain construction
- **Export formats**: JSON, text output

## Security Research Use Only

This tool is designed for:
- Binary exploitation research
- Reverse engineering education
- Penetration testing (authorized)
- CTF competitions

**Legal Notice**: Use only on systems you own or have explicit permission to test.
