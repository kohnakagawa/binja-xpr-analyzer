#
# (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
#
import binaryninja
from binaryninja.interaction import get_open_filename_input
from binaryninja.enums import HighLevelILOperation
import sys
import re
from typing import Dict, Optional, List


def annotate_remediation_builder_dump_internal(
    bv: binaryninja.BinaryView, dump: str
) -> str:
    assess_funcs = get_assess_functions(bv)

    pattern = r"0x[0-9A-Fa-f]{16}"

    def replace_hex(match):
        hex_addr = match.group(0)
        addr = int(hex_addr, 16)
        if addr in assess_funcs.keys():
            return f"{hex_addr} ({assess_funcs[addr]})"
        else:
            return hex_addr

    return re.sub(pattern, replace_hex, dump)


def annotate_remediation_builder_dump(bv: binaryninja.BinaryView):
    text_fields = [
        binaryninja.interaction.MultilineTextField("Dump", ""),
    ]
    popup_title = "Please enter RemediationBuilder dump"
    if not binaryninja.interaction.get_form_input(text_fields, popup_title):
        print("User canceled the operation.")
        return
    annotated_result = annotate_remediation_builder_dump_internal(
        bv, text_fields[0].result
    )
    binaryninja.interaction.show_plain_text_report(
        "XPR Protocol Analyzer: Result", annotated_result
    )


def match_func_ptr_assignment_hlil(
    insn: binaryninja.highlevelil.HighLevelILInstruction, result_var_name: str
):
    if insn.operation != binaryninja.HighLevelILOperation.HLIL_ASSIGN:
        return False

    if insn.dest.operation != binaryninja.HighLevelILOperation.HLIL_DEREF:
        return False

    if insn.dest.src.operation != binaryninja.HighLevelILOperation.HLIL_ADD:
        return False

    if insn.dest.src.left.operation != binaryninja.HighLevelILOperation.HLIL_VAR:
        return False

    if insn.dest.src.left.var.name != result_var_name:
        return False

    if insn.src.operation != binaryninja.HighLevelILOperation.HLIL_CONST_PTR:
        return False

    return True


def get_assess_function_for_tailcall_case(
    bv: binaryninja.BinaryView,
    hlil_insn: binaryninja.highlevelil.HighLevelILInstruction,
    func_addr: int,
) -> Optional[int]:
    if not hasattr(hlil_insn, "params"):
        print(
            f"HLIL instruction at {hex(hlil_insn.address)} does not have params",
            file=sys.stderr,
        )
        return None

    candidates = list()
    for param in hlil_insn.params:
        if not hasattr(param, "constant"):
            continue
        if bv.get_function_at(param.constant) is None:
            continue
        candidates.append(param.constant)

    if len(candidates) != 1:
        print(
            f"Number of candidates is {len(candidates)} at {hex(func_addr)}", file=sys.stderr
        )
        print("This should not occur, so please check!", file=sys.stderr)
        return None
    return candidates[0]


def get_assess_function_for_return_case(
    bv: binaryninja.BinaryView,
    hlil_insn: binaryninja.highlevelil.HighLevelILInstruction,
    remaining_hlil_insns: List[binaryninja.highlevelil.HighLevelILInstruction],
    func_addr: int,
) -> Optional[int]:
    if not hasattr(hlil_insn, "src"):
        print(
            f"HLIL instruction at {hex(hlil_insn.address)} does not have src",
            file=sys.stderr,
        )
        return None

    candidates = list()
    result_var_name = hlil_insn.src[0].var.name
    for hlil_insn in remaining_hlil_insns:
        if match_func_ptr_assignment_hlil(hlil_insn, result_var_name):
            if bv.get_function_at(hlil_insn.src.constant) is None:
                continue
            candidates.append(hlil_insn.src.constant)

    if len(candidates) != 1:
        print(
            f"Number of candidates is {len(candidates)} at {hex(func_addr)}", file=sys.stderr
        )
        print("This should not occur, so please check!", file=sys.stderr)
        return None
    return candidates[0]


# assess function address -> assess function name
def get_assess_functions(bv: binaryninja.BinaryView) -> Dict[int, str]:
    result = dict()
    for sym in bv.get_symbols():
        if not (
            sym.name.startswith("pwt of RemediationBuilder.")
            and sym.name.endswith("ConditionConvertible")
        ):
            continue

        condition_name = sym.name.split(" ")[2].split(".")[-1]
        protocol_name = sym.name.split(" ")[-1].split(".")[-1]
        print(f"Getting assess function for {condition_name}")

        # Skip AnyServiceCondition, AnySafariAppExtensionCondition, AnyProcessCondition, AnyFileCondition
        if condition_name.endswith("Condition"):
            print(
                f"{condition_name} is not a target RemediationBuilder condition, skipping it"
            )
            continue
        func_addr = bv.read_pointer(sym.address + 8)
        if (func := bv.get_function_at(func_addr)) is None:
            print(f"Cannot get function at {hex(func_addr)}", file=sys.stderr)
            continue

        assess_function_name = f"Assess of {condition_name} for {protocol_name}"
        *remaining_hlil_insns, last_hlil_insn = func.hlil.instructions
        if last_hlil_insn.operation == binaryninja.HighLevelILOperation.HLIL_TAILCALL:
            if (
                candidate := get_assess_function_for_tailcall_case(
                    bv, last_hlil_insn, func_addr
                )
            ) is not None:
                result[candidate] = assess_function_name
            else:
                print(
                    f"Cannot get assess function pointer for {condition_name}",
                    file=sys.stderr,
                )
        elif last_hlil_insn.operation == binaryninja.HighLevelILOperation.HLIL_RET:
            if (
                candidate := get_assess_function_for_return_case(
                    bv, last_hlil_insn, remaining_hlil_insns, func_addr
                )
            ) is not None:
                result[candidate] = assess_function_name
            else:
                print(
                    f"Cannot get assess function pointer for {condition_name}",
                    file=sys.stderr,
                )
        else:
            print(
                f"This pattern for {condition_name} is not recognized by this plugin. Please file an issue at https://github.com/FFRI/binja-xpr-analyzer/issues",
                file=sys.stderr,
            )

    return result


def annotate_assess_funcs(bv: binaryninja.BinaryView):
    assess_functions = get_assess_functions(bv)
    if len(assess_functions) == 0:
        print("No symbols were added", file=sys.stderr)
        print(
            "Before running this script, you need to run 'Swift Analyzer\\Add static type metadata'",
            file=sys.stderr,
        )
        print(
            "You can download Binja Swift Analyzer from https://github.com/FFRI/binja-swift-analyzer",
            file=sys.stderr,
        )
        return

    for addr, sym in assess_functions.items():
        new_symbol = binaryninja.Symbol(
            binaryninja.SymbolType.FunctionSymbol, addr, sym
        )
        bv.define_user_symbol(new_symbol)

        
def is_in_section(addr, section_start, size):
    return section_start <= addr < section_start + size

    
def annotate_obfuscated_string(bv):
    functions = bv.get_functions_by_name("mod_init_func_0")
    if len(functions) != 1:
        print("mod_init_func_0 was not found", file=sys.stderr)
        return
    function = functions[0]

    xpr_section_dump = get_open_filename_input("Select XPR section dump", "*.bin")
    with open(xpr_section_dump, "rb") as f:
        xpr_section = f.read()

    xpr_section_offset = bv.get_section_by_name("__bss").start

    for hlil in function.hlil.instructions:
        if hlil.operation != HighLevelILOperation.HLIL_ASSIGN:
            continue

        if hlil.dest.operation != HighLevelILOperation.HLIL_DEREF:
            continue

        if hlil.dest.src.operation != HighLevelILOperation.HLIL_CONST_PTR:
            continue

        if hlil.src.operation != HighLevelILOperation.HLIL_CONST_PTR:
            continue

        dest_const = hlil.dest.src.constant
        src_const = hlil.src.constant

        if not is_in_section(src_const, xpr_section_offset, len(xpr_section)):
            continue

        src_const_offset = src_const - xpr_section_offset
        xpr_section[src_const_offset]
        string_data = b''
        while src_const_offset < len(xpr_section) and xpr_section[src_const_offset] != 0:
            string_data += bytes([xpr_section[src_const_offset]])
            src_const_offset += 1
        
        try:
            decoded_string = string_data.decode('utf-8')
        except UnicodeDecodeError:
            print(f"Failed to decode string at {hex(dest_const)}", file=sys.stderr)
            decoded_string = string_data.decode('utf-8', errors='replace')
        
        print(f"Decoded string: {decoded_string}")
        print(f"Annotating {decoded_string} at {hex(dest_const)}")
        new_symbol = binaryninja.Symbol(binaryninja.SymbolType.DataSymbol, dest_const, decoded_string)
        bv.define_user_symbol(new_symbol)

        print(f"Also annotating accessor to {decoded_string} and functions called by swift_once")
        for ref in bv.get_code_refs(dest_const):
            if function != ref.function:
                new_symbol = binaryninja.Symbol(binaryninja.SymbolType.FunctionSymbol, ref.function.start, f"get_{decoded_string}")
                bv.define_user_symbol(new_symbol)
                annotate_functions_called_by_swift_once(bv, ref.function, decoded_string)


def annotate_functions_called_by_swift_once(bv: binaryninja.BinaryView, function: binaryninja.Function, symbol_name: str):
    for ref in bv.get_code_refs(function.start):
        for ref2 in bv.get_code_refs(ref.function.start):
            if hlil_inst := ref2.function.get_llil_at(ref2.address).hlil:
                if "swift_once" in str(hlil_inst):
                    new_symbol = binaryninja.Symbol(binaryninja.SymbolType.FunctionSymbol, ref.function.start, f"swift_once_{symbol_name}")
                    bv.define_user_symbol(new_symbol)


binaryninja.PluginCommand.register(
    "XPR Analyzer\\Annotate _assess functions",
    "Annotate _assess functions",
    annotate_assess_funcs,
)
binaryninja.PluginCommand.register(
    "XPR Analyzer\\Annotate RemediationBuilder dump",
    "Annotate RemediationBuilder dump",
    annotate_remediation_builder_dump,
)
binaryninja.PluginCommand.register(
    "XPR Analyzer\\Annotate obfuscated strings",
    "Annotate obfuscated strings",
    annotate_obfuscated_string,
)
