import math
from concurrent.futures import ProcessPoolExecutor, as_completed
from queue import Queue

from loguru import logger

import config
import metrics_filter.main
from extractor import Extractor as MetricsExtractor
from models import QueueMessage, PBarMessage, ComponentEnum
from .main import init_filter, check_is_vul

loc_dict = dict()


def initialization(file_pair_list):
    logger.info("Initialize Metrics Filter")
    init_filter(config.metrics_choice, config.threshold_recall)
    for vul_file, _ in file_pair_list:
        with open(vul_file) as f:
            extractor = MetricsExtractor(f.read())
        loc = int(extractor.get_metric(0))
        if loc in loc_dict:
            loc_dict[loc].append(vul_file)
        else:
            loc_dict[loc] = [vul_file]


def detect(input_queue: Queue[QueueMessage], output_queue: Queue[QueueMessage], pbar_queue):
    with ProcessPoolExecutor(max_workers=config.metrics_filter_workers) as executor:
        futures = {}

        def process_future(future):
            try:
                is_vul, metrics, tokens = future.result()
            except Exception as e:
                pbar_queue.put(PBarMessage(ComponentEnum.metrics_filter, False))
                logger.error(f"{str(e)}")
            else:
                pbar_queue.put(PBarMessage(ComponentEnum.metrics_filter, is_vul))
                if not is_vul:
                    return
                vul_info = futures[future]
                target_loc = metrics[0]  # 0 always LOC
                matched_list = []
                upper_bound = int(math.floor(target_loc / config.hash_sim_threshold)) + 1
                lower_bound = int(math.ceil(target_loc * config.hash_sim_threshold))
                for l in range(lower_bound, upper_bound):
                    if l in loc_dict:
                        matched_list.extend(loc_dict[l])
                output_queue.put(QueueMessage(vul_info.function_code, vul_info.function_path, matched_list, {
                    "metrics": metrics,
                    "tokens": tokens
                }))

        logger.info("Metrics Filter Starts")
        while True:
            vul_info = input_queue.get()

            if vul_info.function_path == "__end_of_detection__":
                for future in as_completed(futures.keys()):
                    process_future(future)
                output_queue.put(vul_info)
                logger.info("Metrics Filter Finished!")
                break

            future = executor.submit(
                check_is_vul, vul_info.function_code, vul_info.function_path
            )
            futures[future] = vul_info

            done_futures = []
            for future in futures.keys():
                if not future.done():
                    continue
                process_future(future)
                done_futures.append(future)

            for future in done_futures:
                futures.pop(future)
