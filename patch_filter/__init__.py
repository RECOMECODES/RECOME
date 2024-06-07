from concurrent.futures import ProcessPoolExecutor, as_completed
from loguru import logger
from queue import Queue

import config
from models import QueueMessage, PBarMessage, ComponentEnum
from pickle_manager import load_pickle, cached_line_hash_path, cached_diff_line_path
from .main import vuln_info_dict, VulnInfo, find_best_match_list, get_line_hash, get_diff_lines_hash


def initialization(file_pair_list):
    logger.info("Initialize Patch Filter")
    for vuln_file, patch_file in file_pair_list:
        vul_hash_dict = load_pickle(cached_line_hash_path(vuln_file))
        patch_hash_dict = load_pickle(cached_line_hash_path(patch_file))
        diff_line_hash = load_pickle(cached_diff_line_path(vuln_file))

        vuln_info_dict[vuln_file] = VulnInfo(
            patch=patch_file,
            vuln_hash_dict=vul_hash_dict,
            patch_hash_dict=patch_hash_dict,
            diff_line_hash=diff_line_hash,
        )


def detect(
        input_queue: Queue[QueueMessage],
        output_queue: Queue[QueueMessage],
        pbar_queue: Queue[PBarMessage],
):
    with ProcessPoolExecutor(max_workers=config.patch_filter_workers) as executor:
        futures = {}

        def process_future(future):
            try:
                vul_list = future.result()
                is_vul = len(vul_list) != 0
            except Exception as e:
                pbar_queue.put(PBarMessage(ComponentEnum.patch_filter, False))
                logger.error(f"{str(e)}")
            else:
                pbar_queue.put(PBarMessage(ComponentEnum.patch_filter, is_vul))
                if not is_vul:
                    return
                vul_info = futures[future]
                output_queue.put(
                    QueueMessage(vul_info.function_code, vul_info.function_path, vul_list, vul_info.context))

        logger.info("Patch Filter Starts")
        while True:
            vul_info = input_queue.get()
            if vul_info.function_path == "__end_of_detection__":
                for future in as_completed(futures.keys()):
                    process_future(future)
                output_queue.put(vul_info)

                logger.info("Patch Filter Finished!")
                break
            #
            # dump_dir = os.path.join("GT_dump", vul_info.function_path.split("/")[-1])
            # os.makedirs(dump_dir, exist_ok=True)
            # # dump target
            # with open(os.path.join(dump_dir, "target.vul"), "w") as fw:
            #     fw.write(vul_info.function_code)
            # # dump patch:
            # for i in range(len(vul_info.matched_vul_list)):
            #     with open(vuln_info_dict[vul_info.matched_vul_list[i]].patch) as fr:
            #         code = fr.read()
            #     with open(os.path.join(dump_dir, f"patch.{i}.vul"), "w") as fw:
            #         fw.write(code)

            future = executor.submit(
                find_best_match_list, vul_info.function_code, vul_info.matched_vul_list
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
