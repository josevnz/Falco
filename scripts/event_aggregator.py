#!/usr/bin/env python3
"""
Aggregate Falco events to make it easier to override rules
Jose Vicente Nunez (kodegeek.com@protonmail.com)
"""
import json
import re
from argparse import ArgumentParser
from pathlib import Path
from rich.console import Console
from falcotutor.ui import EventDisplayApp, create_event_table, add_rows_to_create_event_table


def filter_events(journalctl_out: Path) -> dict[any, any]:
    """
    :param journalctl_out:
    :return:
    """
    with open(journalctl_out, 'r') as journalctl_file:
        for row in journalctl_file:
            if re.search("^{", row):
                data = json.loads(row)
                if 'rule' in data and 'output_fields' in data:
                    yield data


def aggregate_events(local_event: dict[any, any], aggregated_events: dict[any, any]):
    rule = local_event['rule']
    if rule not in aggregated_events:
        aggregated_events[rule] = {
            'count': 0,
            'priority': local_event['priority'],
            'last_timestamp': "",
            'last_fields': ""
        }
    aggregated_events[rule]['count'] += 1
    aggregated_events[rule]['last_timestamp'] = local_event['time']
    del local_event['output_fields']['evt.time']
    aggregated_events[rule]['last_fields'] = json.dumps(local_event['output_fields'], indent=True)


if __name__ == "__main__":
    CONSOLE = Console()
    AGGREGATED = {}
    PARSER = ArgumentParser(description=__doc__)
    PARSER.add_argument(
        "falco_event",
        action="store"
    )
    ARGS = PARSER.parse_args()
    try:
        event_table = create_event_table()
        for event in filter_events(ARGS.falco_event):
            aggregate_events(local_event=event, aggregated_events=AGGREGATED)
        add_rows_to_create_event_table(AGGREGATED, event_table)
        EventDisplayApp.run(
            event_file=ARGS.falco_event,
            title="Falco aggregated events report",
            event_table=event_table
        )
    except KeyboardInterrupt:
        CONSOLE.print("[bold]Program interrupted...[/bold]")
