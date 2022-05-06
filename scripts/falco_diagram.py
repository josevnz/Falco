#!/usr/bin/env python3
"""
Generate the basic Falco architecture diagram used on the tutorial
Jose Vicente Nunez (kodegeek.com@protonmail.com)
"""
from pathlib import Path

from diagrams import Diagram
from diagrams.custom import Custom
from diagrams.onprem.monitoring import Grafana
from diagrams.onprem.monitoring import Prometheus
from diagrams.onprem.monitoring import PrometheusOperator
from argparse import ArgumentParser

BASEDIR = Path(__file__).parent.parent
FALCO_LOGO = str(BASEDIR.joinpath('falcotutor').joinpath('img').joinpath('falco.png'))

if __name__ == "__main__":

    PARSER = ArgumentParser(description=__doc__)
    PARSER.add_argument(
        "diagram_name",
        action="store",
        help="Destination of the diagram"
    )
    ARGS = PARSER.parse_args()

    with Diagram("Falco monitoring", show=True, direction="TB", filename=ARGS.diagram_name):
        Custom("Falco monitoring agent", FALCO_LOGO) >> \
            PrometheusOperator("Falco-Exporter") >> \
            Prometheus("Prometheus Metric scraper") >> \
            Grafana("Grafana Event display")
