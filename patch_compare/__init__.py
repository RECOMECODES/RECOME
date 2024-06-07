import os.path
from queue import Queue

from loguru import logger

import config
from models import QueueMessage, PBarMessage, ComponentEnum
from .main import PatchComparator

Comparator: PatchComparator

bypass = False

def initialization():
    global Comparator
    logger.info("Initialize Patch Comparator")
    Comparator = PatchComparator(os.path.join(config.cache_path, "metrics"))


def detect(input_queue: Queue[QueueMessage], output_queue: Queue[QueueMessage], pbar_queue: Queue[PBarMessage]):
    logger.info("Patch Comparator Starts")
    while True:
        vul_info = input_queue.get()
        if vul_info.function_path == "__end_of_detection__":
            output_queue.put(vul_info)
            pbar_queue.put(PBarMessage(ComponentEnum.end_of_detection, False))

            logger.info("Patch Comparator Finished!")
            break
        if config.bypass_patch_compare:
            pbar_queue.put(PBarMessage(ComponentEnum.patch_compare, True))
            output_queue.put(vul_info)
        vul_list = Comparator.find_best_match_list(vul_info.context["metrics"], vul_info.matched_vul_list)

        pbar_queue.put(PBarMessage(ComponentEnum.patch_compare, len(vul_list) != 0))
        if len(vul_list) != 0:
            output_queue.put(QueueMessage(vul_info.function_code, vul_info.function_path, vul_list, {}))
