import os
import re


# filter out LOC < 3 function
def function_purification(code: str) -> str:
    code = re.sub('\/\*[\w\W]*?\*\/', "", code)
    code = re.sub(r'//.*?\n', "\n", code)
    code = re.sub(r"[^\x00-\x7F]+", "", code)
    code = re.sub(r"^#.*", "", code, flags=re.MULTILINE)

    # remove the empty line to compact the code
    purified_code_lines = list(filter(lambda c: len(c.strip()) != 0, code.split("\n")))
    # Counting the line which blank or contain only 1 char, We do not consider very short functions
    for i in range(len(purified_code_lines)):
        purified_code_lines[i] = purified_code_lines[i].strip(" \t\n\r\f\v")
        # purified_code_lines[i] = re.sub('\s+', '', purified_code_lines[i])
    return "\n".join(purified_code_lines)


def abs_listdir(directory: str):
    return [os.path.join(directory, path) for path in os.listdir(directory)]
