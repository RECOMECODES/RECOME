import concurrent.futures
import difflib
from collections import Counter, namedtuple
from typing import List

import mmh3

import config

VulnInfo = namedtuple(
    "VulnInfo", ["patch", "vuln_hash_dict", "patch_hash_dict", "diff_line_hash"]
)
vuln_info_dict = {}


def norm_line(line_list: List[str]) -> List[str]:
    return list(map(lambda line: line.strip(), line_list))


def diff_lines(left_codes, right_codes):
    left_codes = norm_line(left_codes)
    right_codes = norm_line(right_codes)

    differ = difflib.Differ()
    diff = list(differ.compare(left_codes, right_codes))

    left_diff = []
    right_diff = []

    left = 0
    right = 0
    for line in diff:
        if line.startswith("- "):
            left_diff.append(left_codes[left])
            left += 1
        elif line.startswith("+ "):
            right_diff.append(right_codes[right])
            right += 1
        elif not line.startswith("? ") and line.strip() != "":
            left += 1
            right += 1

    return left_diff, right_diff


def line_hash(code_line):
    return mmh3.hash(code_line.strip(), config.mmh_seed)


def get_line_hash(code):
    lines_hash_dict = Counter()
    for line in code.splitlines():
        lines_hash_dict[line_hash(line)] += 1

    return lines_hash_dict


def get_diff_lines_hash(vul_code, patch_code, filter_lines=None):
    if filter_lines is None:
        filter_lines = []
    vuln_diff_line, patch_diff_line = diff_lines(
        vul_code.splitlines(), patch_code.splitlines()
    )

    if filter_lines:
        vuln_diff_line = [line for line in vuln_diff_line if line not in filter_lines]
        patch_diff_line = [line for line in patch_diff_line if line not in filter_lines]

    return (
        list(map(line_hash, vuln_diff_line)),
        list(map(line_hash, patch_diff_line)),
    )


def check_diff_lines(lines, vul_hash_dict, patch_hash_dict, dst_hash_dict):
    for line in lines:
        if (
                vul_hash_dict[line] != patch_hash_dict[line]
                and dst_hash_dict[line] != vul_hash_dict[line]
        ):
            return False
    return True


def process_vuln(vuln_name, vuln_info_dict, dst_hash_dict):
    vuln_info = vuln_info_dict[vuln_name]
    vuln_hash_dict, patch_hash_dict = Counter(vuln_info.vuln_hash_dict), Counter(
        vuln_info.patch_hash_dict
    )
    del_lines, add_lines = vuln_info.diff_line_hash

    if not check_diff_lines(
            del_lines, vuln_hash_dict, patch_hash_dict, dst_hash_dict
    ) or not check_diff_lines(
        add_lines, vuln_hash_dict, patch_hash_dict, dst_hash_dict
    ):
        return None

    return vuln_name


def check_patch(dst_hash_dict, matched_vulns, vuln_info_dict):
    with concurrent.futures.ProcessPoolExecutor() as executor:  # There won't be too many vul,patch pairs here
        results = list(
            executor.map(
                process_vuln,
                matched_vulns,
                [vuln_info_dict] * len(matched_vulns),
                [dst_hash_dict] * len(matched_vulns),
            )
        )

    vulns = [result for result in results if result is not None]
    return vulns


def find_best_match_list(code, matched_vulns):
    return check_patch(get_line_hash(code), matched_vulns, vuln_info_dict)
