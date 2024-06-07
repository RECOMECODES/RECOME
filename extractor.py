import math
import re
from math import log2
from typing import List

from tree_sitter import Parser, Language, Node

import config

operators = ['!=', '!', '%=', '%', '&&', '&=', '&', '||', '|=', '|', '(', ')', '*=', '*', '++', '+=', '+', '--', '-=',
             '->', '-', '...', '.', '/=', '/', '::', ':', '<<=', '<<', '<=', '<', '==', '=', '>>=', '>=', '>>', '>',
             '?', '[', ']', '^=', '^', '{', '}', '~', ',', ';']


class AST:
    def __init__(self, code: str):
        self._ast_parser = Parser()
        cpp_language = Language(config.ast_parser_path, 'cpp')
        self._ast_parser.set_language(cpp_language)
        raw_code = code.encode("utf8")
        self.ast_tree = self._ast_parser.parse(raw_code)

    # "TokenList", ["type", "name", "start", "end"]

    def get_tokens(self):
        token_list = []
        known_token_dict = {}

        def dfs(node: Node, parent_node_types: List[str]):
            if "type_identifier" in node.type:
                # TYPE Token
                token_list.append(("TYPE", str(node.text), node.start_point, node.end_point))
            elif "literal" in node.type:
                # LITR Token
                token_list.append(("LITR", str(node.text), node.start_point, node.end_point))
            elif node.type == "identifier":
                if node.text in known_token_dict:
                    token_list.append((known_token_dict[node.text], str(node.text), node.start_point, node.end_point))
                else:
                    for parent_node_type in parent_node_types:
                        if parent_node_type == "parameter_declaration":
                            token_list.append(("PARM", str(node.text), node.start_point, node.end_point))
                            known_token_dict[node.text] = "PARM"
                            break
                        if parent_node_type == "init_declarator":
                            token_list.append(("LVAR", str(node.text), node.start_point, node.end_point))
                            known_token_dict[node.text] = "LVAR"
                            break
                        if parent_node_type == "function_declarator" or parent_node_type == "call_expression":
                            token_list.append(("FUNC", str(node.text), node.start_point, node.end_point))
                            known_token_dict[node.text] = "FUNC"
                            break
                    else:
                        # print("Unknown ID found", node.text)
                        token_list.append(("UKID", str(node.text), node.start_point, node.end_point))
            elif "identifier" in node.type:
                # print("Unknown ID found", node.text)
                token_list.append(("UKID", str(node.text), node.start_point, node.end_point))
            for child in node.children:
                dfs(child, [node.type] + parent_node_types)

        dfs(self.ast_tree.root_node, [])
        token_list.sort(key=lambda token: token[2])
        return token_list


class Extractor:
    metrics_list = ["LOC", "XMET", "NEXP", "LOOP", "NOS", "NOA", "VDEC", "NCLTRL", "NSLTRL",
                    "NNLTRL", "NOPR", "NAND", "HVOC", "HEFF", "HDIF", "HVOL", "CC", "MI"]
    # BUG 
    # metrics_to_index = {metrics_list[index]: index for index in range(len(metrics_list))}

    LOC = 0
    XMET = 0  # external method called FINISH
    NEXP = 0  # expressions
    LOOP = 0  # loops (for,while) FINISH
    NOS = 0  # statement
    NOA = 0  # arguments FINISH
    VDEC = 0  # variables declared
    NCLTRL = 0  # Charater literals
    NSLTRL = 0  # string literals
    NNLTRL = 0  # Numerical literals
    NOPR = 0  # operators
    NAND = 0  # operand
    HVOC = 0  # Halstead vocabulary
    HEFF = 0  # Halstead effort to implement
    HDIF = 0  # Halstead difficulty to implement
    HVOL = 0  # Halstead Volume
    CC = 0
    MI = 0

    def __init__(self, code):
        self.operands = dict()
        self.operators = dict()

        self.code = code
        self.code_lines = code.split("\n")

        self.metrics_to_index = {self.metrics_list[index]: index for index in range(len(self.metrics_list))}
        self.metrics_init = dict(LOC=False, AST=False, HALSTEAD=False, CC=False, MI=False)
        self._ast: AST

    def get_ast(self):
        if not self.metrics_init["AST"]:
            self._calc_metric(1)
        return self._ast

    def get_metrics(self, indexes: list):
        return [self.get_metric(index) for index in indexes]

    def get_metric(self, index: int):
        self._calc_metric(index)
        return self.__getattribute__(self.metrics_list[index])

    def _calc_metric(self, index: int):
        if index == 0 and not self.metrics_init["LOC"]:  # LOC
            self.metrics_init["LOC"] = True
            self._loc(self.code_lines)
        elif 1 <= index <= 9 and not self.metrics_init["AST"]:  # XMET~NNCTRL
            self.metrics_init["AST"] = True
            self._visit_metrics(self.code)
        elif 10 <= index <= 15 and not self.metrics_init["HALSTEAD"]:  # Halstead stuff
            self.metrics_init["HALSTEAD"] = True
            self._visit_halstead(self.code)
        elif index == 16 and not self.metrics_init["CC"]:  # CC
            self.metrics_init["CC"] = True
            self._visit_CyclomaticComplexity(self.code)
        elif index == 17 and not self.metrics_init["MI"]:
            # MI need Halstead stuff & CC & LOC
            self._calc_metric(0)
            self._calc_metric(10)
            self._calc_metric(16)
            self.metrics_init["MI"] = True
            self._visit_MaintainabilityIndex()

    def _loc(self, purified_code_lines):
        loc = 0
        for i in range(len(purified_code_lines)):
            purified_code_lines[i] = purified_code_lines[i].strip()
            loc += 1 if len(purified_code_lines[i]) > 1 else 0
        self.LOC = loc
        return "\n".join(purified_code_lines)

    def _get_ast_token(self, current_node):
        if current_node.type == 'declaration':
            self.VDEC += 1
        elif current_node.type == 'argument_list':
            value = current_node.text.decode('utf-8')
            if value != '()':
                value = value.split(',')
                self.NOA += len(value)
        elif current_node.type == 'number_literal':
            self.NNLTRL += 1
        elif current_node.type == 'string_literal':
            self.NSLTRL += 1
        elif current_node.type == 'char_literal':
            self.NCLTRL += 1
        elif current_node.type in ['binary_expression', 'call_expression', 'parenthesized_expression',
                                   'cast_expression', 'pointer_expression',
                                   'sizeof_expression', 'comma_expression', 'assignment_expression',
                                   'field_expression', 'new_expression',
                                   'unary_expression', 'update_expression', 'subscript_expression',
                                   'delete_expression', 'conditional_expression',
                                   'offsetof_expression', 'compound_literal_expression', 'alignof_expression',
                                   'gnu_asm_expression', 'lambda_expression']:
            if current_node.type == 'call_expression':
                self.XMET += 1
            self.NEXP += 1
        elif current_node.type in ['compound_statement', 'if_statement', 'expression_statement', 'for_statement',
                                   'break_statement',
                                   'return_statement', 'while_statement', 'switch_statement', 'case_statement',
                                   'do_statement',
                                   'goto_statement', 'labeled_statement', 'continue_statement', 'init_statement',
                                   'throw_statement', 'try_statement']:

            if current_node.type in ['do_statement', 'for_statement', 'while_statement']:
                self.LOOP += 1
            self.NOS += 1

    def _visit_metrics(self, code):
        self._ast = AST(code)
        root_node = self._ast.ast_tree.root_node
        # Traverse
        traverse_stack = [root_node]
        while traverse_stack:
            current_node = traverse_stack.pop()
            self._get_ast_token(current_node)
            traverse_stack.extend(reversed(current_node.children))

    def _visit_halstead(self, code):
        lines = code.split('\n')
        for line in lines:
            # match string constant
            pattern = re.compile(r'"(?:[^"]|\\")*[^\\]"')
            for s in pattern.findall(line):
                if s == ' ':
                    continue
                if s in self.operands:
                    self.operands[s] = self.operands[s] + 1
                else:
                    self.operands[s] = 1
            line = re.sub(pattern, ' ', line)

            # match operators
            for key in operators:
                self.operators[key] = self.operators.get(
                    key, 0) + line.count(key)
                line = line.replace(key, ' ')

            # match operands
            for token in line.split():
                if token == ' ':
                    continue
                if token in self.operands:
                    self.operands[token] = self.operands[token] + 1
                else:
                    self.operands[token] = 1

        n1, N1, n2, N2 = 0, 0, 0, 0

        # print("OPERATORS:\n")
        for key in self.operators.keys():
            if self.operators[key] > 0 and key not in ")}]":
                n1, N1 = n1 + 1, N1 + self.operators[key]
                # print("{} = {}".format(key, self.operators[key]))

        # print("\nOPERANDS\n")
        for key in self.operands.keys():
            if self.operands[key] > 0:
                n2, N2 = n2 + 1, N2 + self.operands[key]
                # print("{} = {}".format(key, self.operands[key]))

        self.NOPR = N1
        self.NAND = N2
        self.HVOC = N1 + N2
        self.HDIF = n1 * N2 / 2 / n2
        self.HEFF = self.HDIF * (N1 + N2) * log2(n1 + n2)
        self.HVOL = (N1 + N2) * log2(n1 + n2)

    def _visit_CyclomaticComplexity(self, lines):
        pathnum = 1
        lines = lines.split('\n')
        for line in lines:
            pattern1 = r"if"
            pattern2 = r"for"
            pattern3 = r"while"
            pattern4 = r"case"
            pattern5 = r"catch"
            pattern6 = r"&&"
            pattern7 = r"\|\|"
            pattern8 = r"else"
            pattern9 = r"else if"
            pattern10 = r"\?"
            ifs = re.search(pattern1, line)
            fors = re.search(pattern2, line)
            whiles = re.search(pattern3, line)
            cases = re.search(pattern4, line)
            catchs = re.search(pattern5, line)
            ands = re.search(pattern6, line)
            ors = re.search(pattern7, line)
            elses = re.search(pattern8, line)
            elifs = re.search(pattern9, line)
            threes = re.search(pattern10, line)

            if ifs != None:
                pathnum += 1
            if fors != None:
                pathnum += 1
            if whiles != None:
                pathnum += 1
            if cases != None:
                pathnum += 1
            if catchs != None:
                pathnum += 1
            if ands != None:
                pathnum += 1
            if ors != None:
                pathnum += 1
            if elses != None:
                pathnum += 1
            if elifs != None:
                pathnum -= 1
            if threes != None:
                pathnum += 1
        # print('%-15s : CC(%s)' % (file_name.split('\\')[1], pathnum))
        self.CC = pathnum

    def _visit_MaintainabilityIndex(self):
        self.MI = 171 - 5.2 * math.log(self.HVOL, math.e) - 0.23 * (self.CC) - 16.2 * math.log(self.LOC, math.e)


def abstraction(code: str, token_list):
    # [start,end)
    def add_non_token(start_line, start_pos, end_line, end_pos):
        non_token_abst_code = ""
        if start_line == end_line:  # in 1 line
            non_token_abst_code += code_lines[end_line][start_pos:end_pos]
        else:  # in multi line
            # start line
            if start_pos < len(code_lines[start_line]):
                non_token_abst_code += code_lines[start_line][start_pos:] + " \n"
            else:
                non_token_abst_code += "\n"
            # middle line
            for line in range(start_line + 1, end_line):
                non_token_abst_code += code_lines[line] + "\n"
            # end line
            non_token_abst_code += code_lines[end_line][:end_pos]
        return non_token_abst_code

    code_lines = code.split("\n")

    # Non-Token - Token - Non-Token
    abst_code = ""
    for i in range(len(token_list)):
        if i == 0:
            if token_list[i][2] == (0, 0):
                continue
            non_token_end_line, non_token_end_pos = token_list[i][2]
            abst_code += add_non_token(0, 0, non_token_end_line, non_token_end_pos)
        else:
            # included
            non_token_start_line = token_list[i - 1][3][0] if i > 0 else 0
            non_token_start_pos = token_list[i - 1][3][1] if i > 0 else 0
            # not included
            non_token_end_line, non_token_end_pos = token_list[i][2]
            abst_code += add_non_token(non_token_start_line, non_token_start_pos, non_token_end_line, non_token_end_pos)
        abst_code += token_list[i][0]

    # included
    non_token_start_line = token_list[-1][3][0]
    non_token_start_pos = token_list[-1][3][1]
    if non_token_start_line == len(code_lines) - 1 and non_token_start_pos == len(code_lines[-1]):
        abst_code += add_non_token(non_token_start_line, non_token_start_pos, len(code_lines) - 1, len(code_lines[-1]))

    abst_code_lines = [re.sub("\s+", "", abst_codeline) for abst_codeline in abst_code.split("\n")]
    return abst_code_lines
