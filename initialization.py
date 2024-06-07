import mmh3
from multiset import FrozenMultiset
from tqdm import tqdm

import config
import patch_filter
from extractor import Extractor as MetricsExtractor, abstraction
from pickle_manager import dump_pickle, cached_metrics_path, cached_line_hash_path, cached_diff_line_path, \
    cached_abst_line_hash_path


def init(file_pair_list):
    for vul_file, patch_file in tqdm(file_pair_list):
        with open(vul_file) as f:
            vul_extractor = MetricsExtractor(f.read())
        with open(patch_file) as f:
            patch_extractor = MetricsExtractor(f.read())

        vul_metrics = vul_extractor.get_metrics(list(range(18)))
        patch_metrics = patch_extractor.get_metrics(list(range(18)))
        dump_pickle(vul_metrics, cached_metrics_path(vul_file))
        dump_pickle(patch_metrics, cached_metrics_path(patch_file))

        vul_tokens = vul_extractor.get_ast().get_tokens()
        vul_abst_multi_set = FrozenMultiset(mmh3.hash(line, config.mmh_seed) for line in
                                            filter(lambda line: len(line) > 1,
                                                   abstraction(vul_extractor.code, vul_tokens)))
        dump_pickle(vul_abst_multi_set, cached_abst_line_hash_path(vul_file, True))

        vul_line_hash = patch_filter.get_line_hash(vul_extractor.code)
        patch_line_hash = patch_filter.get_line_hash(patch_extractor.code)
        dump_pickle(vul_line_hash, cached_line_hash_path(vul_file))
        dump_pickle(patch_line_hash, cached_line_hash_path(patch_file))

        diff_line_hash = patch_filter.get_diff_lines_hash(vul_extractor.code, patch_extractor.code,
                                                           filter_lines=["{", "}"])
        dump_pickle(diff_line_hash, cached_diff_line_path(vul_file))
