from concurrent.futures import ProcessPoolExecutor, as_completed
from queue import Queue

from loguru import logger

import config
from models import QueueMessage, PBarMessage, ComponentEnum
from pickle_manager import load_pickle, cached_abst_line_hash_path
from .main import vul_set_dict, HashFilter, find_best_match_list


def initialization(file_pair_list):
    logger.info("Initialize Hash Filter")
    for vul_file, _ in file_pair_list:
        vul_set_dict[vul_file.split("/")[-1]] = load_pickle(cached_abst_line_hash_path(vul_file, True))


def detect(
        input_queue: Queue[QueueMessage],
        output_queue: Queue[QueueMessage],
        pbar_queue: Queue[PBarMessage]
):
    with ProcessPoolExecutor(max_workers=config.hash_filter_workers) as executor:
        futures = {}

        def process_future(future):
            try:
                vul_list = future.result()
                is_vul = len(vul_list) != 0
            except Exception as e:
                pbar_queue.put(PBarMessage(ComponentEnum.hash_filter, False))
                logger.error(f"{str(e)}")
            else:
                pbar_queue.put(PBarMessage(ComponentEnum.hash_filter, is_vul))
                if not is_vul:
                    return
                vul_info = futures[future]
                output_queue.put(QueueMessage(vul_info.function_code, vul_info.function_path, vul_list, {
                    "metrics": vul_info.context["metrics"]
                }))

        logger.info("Hash Filter Starts")
        while True:
            vul_info = input_queue.get()
            if vul_info.function_path == "__end_of_detection__":
                for future in as_completed(futures.keys()):
                    process_future(future)
                output_queue.put(vul_info)

                logger.info("Hash Filter Finished!")
                break
            future = executor.submit(
                find_best_match_list, vul_info.function_code, vul_info.function_path, vul_info.matched_vul_list,
                vul_info.context["tokens"]
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