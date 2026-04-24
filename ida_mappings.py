import idaapi
import idc
import idautils
import ida_funcs
import ida_name

try:
    import ida_hexrays
    HEXRAYS_AVAILABLE = ida_hexrays.init_hexrays_plugin()
    if not HEXRAYS_AVAILABLE:
        print("[WARNING] Hex-Rays decompiler is not available. Argument renaming impossible.")
except ImportError:
    ida_hexrays = None
    HEXRAYS_AVAILABLE = False
    print("[WARNING] ida_hexrays module not found. Argument renaming impossible.")

def find_function_by_name(name, offset=0):
    ea = idc.get_name_ea(idaapi.BADADDR, name)
    if ea != idaapi.BADADDR:
        return ea

    if name.startswith("sub_"):
        try:
            addr_str = name[4:]
            addr = int(addr_str, 16) + offset
            if ida_funcs.get_func(addr):
                return addr
        except ValueError:
            pass
    return idaapi.BADADDR

def rename_function(ea, new_name):
    if not ida_funcs.get_func(ea):
        print(f"  [ERROR] No function at address {hex(ea)}.")
        return False

    flags = ida_name.SN_FORCE | ida_name.SN_NOWARN
    if idaapi.set_name(ea, new_name, flags):
        print(f"  [OK] Function renamed: {hex(ea)} -> '{new_name}'")
        return True
    else:
        print(f"  [ERROR] Failed to rename function at {hex(ea)} to '{new_name}'.")
        return False

def rename_function_arguments(func_ea, new_arg_names):
    if not HEXRAYS_AVAILABLE or not new_arg_names:
        return

    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            print(f"    [ERROR] Failed to decompile function at {hex(func_ea)}.")
            return
    except Exception as e:
        print(f"    [ERROR] Decompilation error: {e}")
        return

    lvars = cfunc.get_lvars()
    if not lvars:
        print(f"    [SKIP] Function has no local variables or arguments.")
        return

    try:
        arg_indices = list(cfunc.argidx)
    except AttributeError:
        print(f"    [ERROR] Could not get argument indices (cfunc.argidx missing).")
        return

    if not arg_indices:
        print(f"    [SKIP] Function has no arguments.")
        return

    args = [lvars[i] for i in arg_indices if i < len(lvars)]

    if len(new_arg_names) < len(args):
        print(f"    [WARNING] Fewer argument names ({len(new_arg_names)}) than function arguments ({len(args)}). Only the first ones will be renamed.")
    elif len(new_arg_names) > len(args):
        print(f"    [WARNING] More argument names ({len(new_arg_names)}) than function arguments ({len(args)}). Extra will be ignored.")

    for i, arg in enumerate(args):
        if i >= len(new_arg_names):
            break
        new_name = new_arg_names[i].strip()
        if not new_name:
            continue

        try:
            lsi = ida_hexrays.lvar_saved_info_t()
            lsi.ll = arg
            lsi.name = new_name

            success = ida_hexrays.modify_user_lvar_info(func_ea, ida_hexrays.MLI_NAME, lsi)
            if success:
                print(f"    [OK] Argument '{arg.name}' renamed to '{new_name}'")
            else:
                print(f"    [ERROR] Failed to rename argument '{arg.name}' to '{new_name}'")
        except Exception as e:
            print(f"    [ERROR] Exception while renaming argument: {e}")

    try:
        vu = ida_hexrays.open_pseudocode(func_ea, 0)
        if vu:
            vu.refresh_view(True)
            print(f"    [INFO] Pseudocode view for {hex(func_ea)} refreshed.")
    except Exception:
        pass

def process_rename_file(file_path, offset=0):
    print(f"\n[START] Reading file: {file_path}")
    if offset != 0:
        print(f"[INFO] Using address offset: {hex(offset)}")

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[CRITICAL ERROR] Failed to open file: {e}")
        return

    renamed_funcs_count = 0
    failed_funcs_count = 0

    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        parts = line.split()
        if len(parts) < 2:
            print(f"[WARNING] Line {line_num}: Invalid format, skipped. '{line}'")
            continue

        old_name = parts[0]
        new_func_name = parts[1]
        new_arg_names = parts[2:] if len(parts) > 2 else []

        print(f"\n[PROCESSING] Line {line_num}: '{old_name}' -> '{new_func_name}', Arguments: {new_arg_names}")

        func_ea = find_function_by_name(old_name, offset)
        if func_ea == idaapi.BADADDR:
            print(f"  [ERROR] Function with name '{old_name}' not found in database.")
            failed_funcs_count += 1
            continue

        print(f"  [INFO] Function found at address: {hex(func_ea)}")

        if rename_function(func_ea, new_func_name):
            renamed_funcs_count += 1
            if HEXRAYS_AVAILABLE and new_arg_names:
                rename_function_arguments(func_ea, new_arg_names)
        else:
            failed_funcs_count += 1

    print("\n" + "=" * 60)
    print("PROCESSING COMPLETED")
    print(f"  Successfully renamed functions: {renamed_funcs_count}")
    print(f"  Errors renaming functions: {failed_funcs_count}")
    print("=" * 60)

def main():
    file_path = idaapi.ask_file(False, "*.txt", "Select file with renaming data")
    if not file_path:
        print("[CANCEL] No file selected. Script terminated.")
        return

    use_offset = idaapi.ask_yn(0, "Use additional offset for addresses?")
    offset = 0
    if use_offset == 1:
        offset = idaapi.ask_addr(0, "Enter offset (can be negative, hex or dec)")
        if offset is None or offset == idaapi.BADADDR:
            print("[WARNING] Offset not entered or cancelled, using 0.")
            offset = 0
        else:
            print(f"[INFO] Offset set: {hex(offset) if offset >= 0 else '-' + hex(-offset)}")

    process_rename_file(file_path, offset)

if __name__ == "__main__":
    main()
