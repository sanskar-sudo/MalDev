import re

def process_assembly(assembly_code):
    # 1. Remove mnemonics and their instructions
    cleaned_code = re.sub(r'\b(?:mov|movsxd|ret|cmp|lea|call|inc|jmp|movzx|push|nop|ret|xor|sub|pop|jb|add|je|test)\b.*$', '', assembly_code, flags=re.MULTILINE)

    # 2. Remove all spaces
    cleaned_code = cleaned_code.replace(" ", "")

    # 3. Wrap shellcode every 30 characters
    wrapped_shellcode = re.sub(r'(.{30})', r'\1\n', cleaned_code)

    # 4. Format shellcode
    formatted_shellcode = re.sub(r'(.{2})', r'\\x\1', wrapped_shellcode)
    formatted_shellcode = f'"{formatted_shellcode}"'  # Add enclosing quotes

    return formatted_shellcode

# Example usage
assembly_input = """
PUT ASM HERE and UNSTRIP THE ASM COMMENT!!!!
"""

result = process_assembly(assembly_input)
print(result)
