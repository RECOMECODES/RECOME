from typing import FrozenSet

import mmh3
from loguru import logger
from multiset import FrozenMultiset

import config
from extractor import abstraction

vul_set_dict = dict()


def _jaccard_sim(a: FrozenSet | FrozenMultiset, b: FrozenSet | FrozenMultiset):
    inter = len(a.intersection(b))
    union = (len(a) + len(b)) - inter
    return float(inter) / union


def _debug_similar(code_file, vul_file, jacaard):
    if jacaard < 0.3:
        return False
    rel_code_file = code_file.split("/")[-1]
    rel_vul_file = vul_file.split("/")[-1]
    func = rel_code_file.split("@@@")[0]
    return func in rel_vul_file
    # logger.warning(f"{rel_code_file} ")
    # logger.warning(f"sim to {rel_vul_file}: {jacaard}")


class HashFilter:
    debug = False

    def __init__(self, code, code_file, token_list):
        abst_code_lines = abstraction(code, token_list)
        self.code_set = FrozenMultiset([mmh3.hash(line, config.mmh_seed) for line in
                                        filter(lambda line: len(line) > 1, abst_code_lines)])
        self.code_file = code_file

    def compare(self, matched_vul_list):
        refined_vul_list = []
        name_matched_list = []
        for vul_file in matched_vul_list:
            vul_set = vul_set_dict[vul_file.split("/")[-1]]
            sim = _jaccard_sim(vul_set, self.code_set)
            if self.debug and _debug_similar(self.code_file, vul_file, sim):
                name_matched_list.append((vul_file, sim))
            if sim >= config.hash_sim_threshold:
                refined_vul_list.append(vul_file)
                # logger.debug(f"{self.code_file.split('/')[-1]} is similar to:")
                # logger.debug(f"{vul_file.split('/')[-1]}: {sim}")
        if self.debug:
            if len(name_matched_list) == 0:
                logger.error(f"old_new_funcs missing {self.code_file.split('/')[-1]}")
            elif len(set(refined_vul_list).intersection(set([item[0] for item in name_matched_list]))) == 0:
                logger.warning(f"Hash Filter Failed in {self.code_file.split('/')[-1]}")
                name_matched_list.sort(key=lambda item: item[1], reverse=True)
                for item in name_matched_list:
                    logger.warning(f"Potential Vul: {item[0].split('/')[-1]}: {item[1]}")
        return refined_vul_list


def find_best_match_list(code, code_file, matched_vul_list, token_list):
    hash_filter = HashFilter(code, code_file, token_list)
    return hash_filter.compare(matched_vul_list)
