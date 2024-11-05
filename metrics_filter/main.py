from loguru import logger

import config
from extractor import Extractor as MetricsExtractor

Filter = None


class MetricsFilter:
    # metrics_chosen: The Metrics chosen, a metrics index list.
    # The filter will do the filtering foreach metrics in the list
    # Metrics Threshold: the filtering threshold, lower the threshold -> filtered
    # The value of M.17(MI) is set to the additive inverse of the original value(-MI) here
    # to statisfy the rule we set above

    debug = False

    def __init__(self, metrics_chosen, metrics_threshold):
        self.metrics_chosen = metrics_chosen
        self.metrics_threshold = metrics_threshold

    def is_vul(self, code, path):
        extractor = MetricsExtractor(code)
        metrics = []
        for metric_index, metric_threshold in zip(self.metrics_chosen, self.metrics_threshold):
            metric = extractor.get_metric(metric_index)
            if metric < metric_threshold and not config.bypass_metrics_filter:
                if self.debug:
                    logger.warning(f"Metrics Filter Failed M.{metric_index} in {path.split('/')[-1]}: {metric} < {metric_threshold}")
                return False, None, None
            metrics.append(metric)
        if config.use_full_set:
            metrics = [extractor.get_metric(i) for i in range(18)]
        return True, metrics, extractor.get_ast().get_tokens()


def init_filter(metrics_chosen, metrics_threshold):
    global Filter
    Filter = MetricsFilter(metrics_chosen, metrics_threshold)


def check_is_vul(function_code, function_path):
    if not isinstance(Filter, MetricsFilter):
        raise "Metrics Filter not init"
    return Filter.is_vul(function_code, function_path)
