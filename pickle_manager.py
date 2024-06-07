import os
import pickle

import config

metrics_prefix = os.path.join(config.cache_path, "metrics")
abst_line_hash_prefix = os.path.join(config.cache_path, "abst_line_hash")
line_hash_prefix = os.path.join(config.cache_path, "line_hash")
diff_line_prefix = os.path.join(config.cache_path, "diff_line")


def cached_metrics_path(file_path):
    return os.path.join(metrics_prefix, pickle_filename(file_path))


def cached_abst_line_hash_path(file_path, multiset=False):
    return os.path.join(abst_line_hash_prefix,
                        pickle_filename(file_path).replace(".pickle", ".multi.pickle" if multiset else ".pickle"))


def cached_line_hash_path(file_path):
    return os.path.join(line_hash_prefix, pickle_filename(file_path))


def cached_diff_line_path(file_path):
    return os.path.join(diff_line_prefix, pickle_filename(file_path))


checked = False


def check_dirs():
    return os.path.exists(metrics_prefix) and os.path.exists(line_hash_prefix) and os.path.exists(diff_line_prefix)


def create_dirs():
    global checked
    checked = True
    os.makedirs(metrics_prefix, exist_ok=True)
    os.makedirs(abst_line_hash_prefix, exist_ok=True)
    os.makedirs(line_hash_prefix, exist_ok=True)
    os.makedirs(diff_line_prefix, exist_ok=True)


def dump_pickle(obj, file_path):
    if not checked and not check_dirs():
        create_dirs()
    with open(file_path, "wb") as f:
        pickle.dump(obj, f)


def pickle_filename(filename):
    return filename.split("/")[-1] + ".pickle"


def load_pickle(file_path):
    with open(file_path, "rb") as f:
        return pickle.load(f)
