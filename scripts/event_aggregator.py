#!/usr/bin/env python3
"""
Aggregate Falco events to make it easier to override rules
Jose Vicente Nunez (kodegeek.com@protonmail.com)
"""
import json
import re
from argparse import ArgumentParser
from datetime import datetime, timedelta
from pathlib import Path

TEN_Y_AGO = datetime.now() - timedelta(days=365 * 10)


def filter_events(journalctl_out: Path) -> dict[any, any]:
    """
    {
  "output": "23:04:10.661829867: Warning Shell history had been deleted or renamed (user=josevnz user_loginuid=1000 \
  type=rename command=bash fd.name=<NA> name=<NA> path=<NA> oldpath=/home/josevnz/.bash_history-01.tmp host (id=host))",
  "priority": "Warning",
  "rule": "Delete or rename shell history",
  "source": "syscall",
  "tags": [
    "mitre_defense_evasion",
    "process"
  ],
  "time": "2022-05-04T03:04:10.661829867Z",
  "output_fields": {
    "container.id": "host",
    "container.name": "host",
    "evt.arg.name": null,
    "evt.arg.oldpath": "/home/josevnz/.bash_history-01.tmp",
    "evt.arg.path": null,
    "evt.time": 1651633450661830000,
    "evt.type": "rename",
    "fd.name": null,
    "proc.cmdline": "bash",
    "user.loginuid": 1000,
    "user.name": "josevnz"
  }
}
    :param journalctl_out:
    :return:
    """
    with open(journalctl_out, 'r') as journalctl_file:
        for row in journalctl_file:
            if re.search("^{", row):
                data = json.loads(row)
                if 'rule' in data and 'output_fields' in data:
                    yield data


def aggregate_events(local_event: dict[any, any], aggregated_events: dict[any, any]) -> None:
    if 'rule' not in aggregated_events:
        aggregated_events['rule'] = {
            'count': 0,
            'priority': local_event['priority']
        }
    aggregated_events['rule']['count'] += 1
    aggregated_events['rule']['last_timestamp'] += local_event['time']
    aggregated_events['rule']['last_fields'] += local_event['output_fields']


if __name__ == "__main__":
    AGGREGATED = {}
    PARSER = ArgumentParser(description=__doc__)
    PARSER.add_argument(
        "--timestamp",
        type=datetime.fromisoformat,
        action="store",
        required=False,
        default=TEN_Y_AGO,
        help="Filter by timestamp."
    )
    PARSER.add_argument(
        "falco_event",
        action="store"
    )
    ARGS = PARSER.parse_args()
    for event in filter_events(ARGS.falco_event):
        aggregate_events(local_event=event, aggregated_events=AGGREGATED)
