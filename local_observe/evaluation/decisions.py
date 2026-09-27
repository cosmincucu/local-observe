"""Aligned decision units: one resource and fixed observation window, never truth labels."""
import datetime as dt

from local_observe.inventory.validation import canonical, timestamp, utc_text


def identity(resource, window):
    return canonical({'resource_id': resource, 'window': window})


def signature(decision, kinds):
    return canonical({'decision': decision, 'kinds': sorted(set(kinds))})


def baseline(context, actual):
    """Missing source windows or incomplete arms provide no quiet decision."""
    result = {}
    begin, end = timestamp(context['evaluation']['start']), timestamp(context['evaluation']['end'])
    current = begin
    resources = sorted({row['resource_id'] for row in context['series']})
    while current < end:
        stop = min(current + dt.timedelta(hours=1), end)
        window = {'start': utc_text(current), 'end': utc_text(stop)}
        for resource in resources:
            rows = [row for row in context['series'] if row['resource_id'] == resource]
            covered = all(any(current.timestamp() <= point['ts'] < stop.timestamp() for point in row['rows'])
                          for row in rows)
            kinds = [row['kind'] for row in actual['findings'] if row['resource_id'] == resource
                     and current <= timestamp(row['observed_at']) < stop]
            result[identity(resource, window)] = (signature('tell' if kinds else 'quiet', kinds)
                if actual['status'] == 'measured' and covered else None)
        current = stop
    return result
