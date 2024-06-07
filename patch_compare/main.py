import os
import pickle

from loguru import logger

import config
import pickle_manager


class PatchComparator:

    debug = False

    def __init__(self, cached_metrics_path):
        if config.use_full_set:
            self.metrics_importance = config.metrics_importance
        else:
            self.metrics_importance = [config.metrics_importance[i] for i in config.metrics_choice]
        self.metrics_dict = {}
        for metrics_pickle in filter(lambda path: ".pickle" in path, os.listdir(cached_metrics_path)):
            key = metrics_pickle.replace(".pickle", "")
            with open(pickle_manager.cached_metrics_path(key), "rb") as f:
                metrics = pickle.load(f)
                if config.use_full_set:
                    self.metrics_dict[metrics_pickle.replace(".pickle", "")] = metrics
                else:
                    self.metrics_dict[metrics_pickle.replace(".pickle", "")] = [metrics[i] for i in config.metrics_choice]

    def _compare(self, vector, vul_vector, patch_vector):

        def fix_div_0(item):
            return item if item != 0 else 1

        vul_weight_dist = 0
        patch_weight_dist = 0
        for item, vul_item, patch_item, importance in zip(vector, vul_vector, patch_vector, self.metrics_importance):
            vul_dist = abs(vul_item - item)
            patch_dist = abs(patch_item - item)
            vul_weight_dist += vul_dist / fix_div_0(item) * importance
            patch_weight_dist += patch_dist / fix_div_0(item) * importance
        if vul_weight_dist > patch_weight_dist: # IS distance not similarity. distance longer -> less similar
            if self.debug:
                logger.warning(f"vul metrics: {vul_vector}")
                logger.warning(f"patch metrics: {patch_vector}")
                logger.warning(f"target metrics: {vector}")
                logger.warning(f"{vul_weight_dist} < {patch_weight_dist}, failed")
            return False  # A Patch
        else:
            logger.warning(f"vul metrics: {vul_vector}")
            logger.warning(f"patch metrics: {patch_vector}")
            logger.warning(f"target metrics: {vector}")
            logger.warning(f"{vul_weight_dist} < {patch_weight_dist}, failed")
            return True  # A Vulnerable

    def get_vector(self, file_path):
        # Use In memory dict to store vector
        metrics = self.metrics_dict.get(file_path)
        if metrics is None:
            logger.critical("Patch Compare Attempt to load non-exist file:", file_path)
            raise "Patch Compare Attempt to load non-exist file"
        return metrics

    def find_best_match_list(self, metrics_vector, matched_vul_list):
        matched_list = []
        for vul_file in matched_vul_list:
            vul_file = vul_file.split("/")[-1]
            patch_file = vul_file.replace("OLD", "NEW")
            logger.info(vul_file)
            if self._compare(metrics_vector, self.get_vector(vul_file), self.get_vector(patch_file)):
                matched_list.append(vul_file)
        return matched_list
