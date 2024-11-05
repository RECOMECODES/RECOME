import argparse
import json
import os
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager

from loguru import logger
from tqdm import tqdm

import config
import dataset
import hash_filter
import initialization
import metrics_filter
import patch_compare
import patch_filter
import pickle_manager
from models import PBarMessage, QueueMessage, ComponentEnum
from progress_bar import progress_bar_process

logger.remove()
logger.add(lambda msg: tqdm.write(msg, end=""), colorize=True, level="DEBUG")


def put_dataset_to_queue(dataset: dataset.Base, output_queue, pbar_queue):
    # datasets = []
    for func_path in dataset.get_funcs():
        with open(func_path) as f:
            output_queue.put(QueueMessage(f.read(), func_path, [], []))
            pbar_queue.put(PBarMessage(ComponentEnum.dataset, False))

    output_queue.put(QueueMessage("", "__end_of_detection__", [], []))


def dump_vulnerable_func(input_queue, output_name="vuls.json"):
    vul_dict = {}

    vuls = []
    vul_cnt = 0
    vul_all = 0
    while True:
        vul_info = input_queue.get()
        if vul_info.function_path == "__end_of_detection__":
            break
        vul_cnt += 1

        vuls.append({"id": vul_cnt, "dst": vul_info.function_path, "sim": vul_info.matched_vul_list})

        logger.success(f"[No. {vul_cnt}]Vul Detected in {vul_info.function_path}")
        logger.success("Similar to Vulnerability:")
        for exist_vul in vul_info.matched_vul_list:
            logger.success(exist_vul)
            vul_all += 1

        vul_dict["cnt"] = vul_cnt
        vul_dict["all"] = vul_all
        vul_dict["vul"] = vuls

        logger.info(f"Dumping vulnerable function info to {output_name}")
        with open(output_name, "w") as f:
            json.dump(vul_dict, f, indent=4)

    if vul_cnt == 0:
        vul_dict = {"cnt": vul_cnt, "all": vul_all, "vul": vuls}
        logger.info(f"Dumping vulnerable function info to {output_name}")
        with open(output_name, "w") as f:
            json.dump(vul_dict, f, indent=4)

    logger.info("Dump vulnerable function finished!")


def main(ProjectDataset: dataset.Project, output_name, rebuild_list):
    OldNewFuncsDataset = dataset.OldNewFuncs(
        config.old_new_func_dataset_path, rebuild=("old-new-funcs" in rebuild_list)
    )

    logger.info("Start Initialization")

    vul_func_pairs = OldNewFuncsDataset.get_func_pairs()
    if "project" in rebuild_list or not pickle_manager.check_dirs():
        initialization.init(vul_func_pairs)
    metrics_filter.initialization(vul_func_pairs)
    hash_filter.initialization(vul_func_pairs)
    patch_filter.initialization(vul_func_pairs)
    patch_compare.initialization()

    manager = Manager()
    dataset_queue = manager.Queue(maxsize=100)
    pbar_queue = manager.Queue(maxsize=100)
    metrics_filter_processed_queue = manager.Queue(maxsize=2000)
    hash_filter_processed_queue = manager.Queue(maxsize=1000)
    patch_filter_processed_queue = manager.Queue(maxsize=1000)
    patch_compare_processed_queue = manager.Queue(maxsize=1000)

    logger.info("Start Detection")

    with ProcessPoolExecutor(max_workers=7) as executor:
        futures = [
            executor.submit(
                progress_bar_process,
                len(ProjectDataset.get_funcs()),
                pbar_queue,
                os.path.splitext(output_name)[0] + ".detect_info.json",
            ),
            executor.submit(
                put_dataset_to_queue, ProjectDataset, dataset_queue, pbar_queue
            ),
            executor.submit(
                metrics_filter.detect,
                dataset_queue,
                metrics_filter_processed_queue,
                pbar_queue,
            ),
            executor.submit(
                hash_filter.detect,
                metrics_filter_processed_queue,
                hash_filter_processed_queue,
                pbar_queue
            ),
            executor.submit(
                patch_filter.detect,
                hash_filter_processed_queue,
                patch_filter_processed_queue,
                pbar_queue
            ),
            executor.submit(
                patch_compare.detect,
                patch_filter_processed_queue,
                patch_compare_processed_queue,
                pbar_queue,
            ),
            executor.submit(
                dump_vulnerable_func, patch_compare_processed_queue, output_name
            ),
        ]

        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                exception_traceback = traceback.format_exc()
                logger.error(exception_traceback)

    logger.info("Detection Complete")


BASE_DIR = os.path.dirname(os.path.realpath(__file__))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract data from project dir")
    parser.add_argument("project", type=str, help="Path to the project dir")
    parser.add_argument(
        "--rebuild",
        nargs="*",
        default=["target"],
        choices=["old-new-funcs", "target", "project"],
        help="Rebuild any of the components",
    )
    parser.add_argument(
        "--no-cache", action="store_true", help="Rebuild processed cache"
    )
    args = parser.parse_args()

    ProjectDataset = dataset.Project(
        os.path.join(BASE_DIR, args.project),
        no_cache=args.no_cache,
        rebuild=("target" in args.rebuild),
    )

    project_name = os.path.basename(args.project)
    result_dir = f"result/{project_name}"
    os.makedirs(result_dir, exist_ok=True)

    main(
        ProjectDataset,
        output_name=f"{result_dir}/{project_name}.json",
        rebuild_list=args.rebuild,
    )
