from collections import namedtuple
from enum import Enum

# Output Queue: (function_code, function_patch, matched_vul_list, AST Tree, Metrics Vector)
QueueMessage = namedtuple("QueueMessage", [
    "function_code",
    "function_path",
    "matched_vul_list",
    "context"
])

PBarMessage = namedtuple("PBarMessage", [
    "component",
    "is_vul"
])

ComponentEnum = Enum('ComponentEnum', [
    "nothing",
    "dataset",
    "metrics_filter",
    "hash_filter",
    "patch_filter",
    "patch_compare",
    "end_of_detection"
])
