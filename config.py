import json
import os.path
import yaml
from loguru import logger


def load_config():
    config_file = "config.yml"
    threshold_file = "thresholds.yml"
    if os.path.exists(config_file):
        with open(config_file) as f:
            config = yaml.safe_load(f)
    if os.path.exists(threshold_file):
        with open(threshold_file) as f:
            threshold = yaml.safe_load(f)
    else:
        logger.critical("Missing config.yml")
    return config, threshold


def get_config(key, default_value=None):
    if key not in config:
        if default_value is None:
            logger.critical(f"Missing key {key}")
            raise f"config missing key {key}"
        logger.warning(f"Using default value of key {key}")
    value = config.get(key, default_value)
    logger.info(f"Config {key}: {value}")
    return value


def get_metrics_threshold_importance(metrics_choice, target_threshold):
    str_metrics_choice = json.dumps(metrics_choice)
    if str_metrics_choice not in threshold["metrics_choices"]:
        logger.critical(f"Please choose a metrics list in threshold.yaml, your choice:{str_metrics_choice}")
        raise "Metrics unknown"
    if target_threshold not in threshold["metrics_choices"][str_metrics_choice]:
        logger.critical(f"Please choose threshold in [0.8, 0.9, 0.95], your choice:{target_threshold}")
        raise "Threshold unknown"
    return threshold["metrics_choices"][str_metrics_choice][target_threshold], threshold["all_metrics_importance"]


config, threshold = load_config()

# Universal
cache_path = get_config("cache_path", "cache")
ast_parser_path = get_config("ast_parser_path", "dependency/cppparser.so")
old_new_func_dataset_path = get_config("old_new_func_dataset_path")

# Multiprocess
metrics_filter_workers = get_config("metrics_filter_workers", 1)
hash_filter_workers = get_config("hash_filter_workers", 3)
patch_filter_workers = get_config("patch_filter_workers", 6)

# Metrics
metrics_choice = get_config("metrics_choice")
target_recall = get_config("target_recall", 0.9)
threshold_recall, metrics_importance = get_metrics_threshold_importance(metrics_choice, target_recall)
use_full_set = get_config("use_full_set", False)

# HashFilter
mmh_seed = get_config("mmh_seed", 42)
hash_sim_threshold = get_config("hash_sim_threshold", 0.7)

# Bypassing
bypass_metrics_filter = get_config("bypass_metrics_filter", False)
bypass_patch_compare = get_config("bypass_patch_compare", False)
