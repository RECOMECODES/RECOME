from __future__ import annotations

import json
import queue
import sys

import time

from loguru import logger
from tqdm import tqdm

from models import PBarMessage, ComponentEnum


class PBarCounter:
    def __init__(self):
        self.input = 0
        self.done = 0
        self.offset = 0.0
        self.start = 0.0
        self.last = 0.0

    def _get_time(self):
        return self.offset + self.last - self.start if self.done < self.input else self.offset

    def _stop_timer(self):
        self.offset += time.perf_counter() - self.start
        self.start = time.perf_counter()
        self.last = self.start

    def _start_timer(self):
        self.start = time.perf_counter()
        self.last = self.start

    def _record_time(self):
        self.last = time.perf_counter()

    def increment_input(self):
        if self.input == self.done:
            self._start_timer()
        self.input += 1

    def increment_done(self):
        self.done += 1
        if self.input <= self.done:
            self._stop_timer()
        else:
            self._record_time()

    def passed_rate(self, next_counter: PBarCounter):
        return next_counter.input / max(self.done, 1)

    def speed(self):
        return self.done / max(self._get_time(), 1e-3)


def progress_bar_process(total_cnt, pbar_queue, output_name="detect_info.json"):
    metrics = PBarCounter()
    hash_filter = PBarCounter()
    patch = PBarCounter()
    # syntax = PBarCounter()
    comparator = PBarCounter()
    vul_cnt = 0
    postfix_info = {}
    with tqdm(
            total=total_cnt,
            smoothing=0,
            unit="f",
            bar_format="{n_fmt}/{total_fmt}~{remaining}[{rate_fmt}{postfix}]",
            file=sys.stderr,
    ) as pbar:
        while True:
            try:
                message = pbar_queue.get(timeout=0.1)
            except queue.Empty:
                message = PBarMessage(component=ComponentEnum.nothing, is_vul=False)
                pbar.refresh()
            if message.component == ComponentEnum.end_of_detection:
                # dumping final infos
                with open(output_name, "w") as f:
                    json.dump(postfix_info, f)
                break
            elif message.component == ComponentEnum.dataset:
                metrics.increment_input()
            elif message.component == ComponentEnum.metrics_filter:
                metrics.increment_done()
                if message.is_vul:
                    hash_filter.increment_input()
                else:
                    pbar.update()
            elif message.component == ComponentEnum.hash_filter:
                hash_filter.increment_done()
                if message.is_vul:
                    patch.increment_input()
                else:
                    pbar.update()
            elif message.component == ComponentEnum.patch_filter:
                patch.increment_done()
                if message.is_vul:
                    comparator.increment_input()
                else:
                    pbar.update()
            elif message.component == ComponentEnum.patch_compare:
                comparator.increment_done()
                pbar.update()
                if message.is_vul:
                    vul_cnt += 1
            elif message.component == ComponentEnum.nothing:
                pbar.refresh()
            else:
                logger.error("Unknown Source Components")

            metrics_passed_rate = metrics.passed_rate(hash_filter)
            metrics_speed = metrics.speed()
            hash_passed_rate = hash_filter.passed_rate(patch)
            hash_speed = hash_filter.speed()
            patch_passed_rate = patch.passed_rate(comparator)
            patch_speed = patch.speed()
            comparator_speed = comparator.speed()

            postfix_info = {
                "metrics": "%d/%d(%.1f%%,%.1ff/s)" % (
                    metrics.done,
                    metrics.input,
                    100 * (1 - metrics_passed_rate),
                    metrics_speed,
                ),
                "hash": "%d/%d(%.1f%%,%.2f[%.2f]f/s)" % (
                    hash_filter.done,
                    hash_filter.input,
                    100 * (1 - hash_passed_rate),
                    hash_speed,
                    metrics_passed_rate * metrics_speed,
                ),
                "patch": "%d/%d(%.1f%%,%.2f[%.2f]f/s)" % (
                     patch.done,
                     patch.input,
                     100 * (1 - patch_passed_rate),
                     patch_speed,
                     hash_passed_rate * hash_speed,
                 ),
                "comp.": "%d/%d(%d,%.1f[%.1f]f/h)" % (
                     comparator.done,
                     comparator.input,
                     vul_cnt,
                     comparator_speed,
                     patch_passed_rate * patch_speed,
                 ),
            }
            pbar.set_postfix(postfix_info)
