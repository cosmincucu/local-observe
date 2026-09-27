"""Measure observed review workload without inventing labels or human effort."""
import argparse
import json
from pathlib import Path
from statistics import median
import sys

from local_observe.inventory.validation import timestamp, utc_text


def summarize(journal, *, since, until, quiet_every=24):
    start, end = timestamp(since), timestamp(until)
    if not 0 < (end - start).total_seconds() <= 31 * 86400:
        raise ValueError('Feedback measurement requires a window of at most 31 days')
    if type(quiet_every) is not int or not 1 <= quiet_every <= 1000:
        raise ValueError('Quiet sampling interval must be in 1..1000 cycles')
    rows = journal.db.execute('SELECT cycle_id,document FROM cycles WHERE julianday(started_at)>=julianday(?) '
                              'AND julianday(started_at)<julianday(?) '
                              'ORDER BY started_at,cycle_id LIMIT 3001',
                              (utc_text(start), utc_text(end))).fetchall()
    if len(rows) > 3000:
        raise ValueError('Measurement exceeds 3000 cycles; narrow the interval')
    cycles = {row[0]: json.loads(row[1]) for row in rows}
    reviews = {}
    for row in journal.db.execute('SELECT f.cycle_id,f.document FROM feedback f JOIN cycles c USING(cycle_id) '
                                  'WHERE julianday(c.started_at)>=julianday(?) '
                                  'AND julianday(c.started_at)<julianday(?) '
                                  'AND julianday(f.recorded_at)<julianday(?) ORDER BY f.rowid',
                                  (utc_text(start), utc_text(end), utc_text(end))):
        reviews[row[0]] = json.loads(row[1])
    resources, queue, latencies = set(), [], []
    complete = tells = known = quiet_seen = 0
    for key, cycle in cycles.items():
        resources.update(item['resource_id'] for item in cycle['evidence'])
        complete += cycle['status'] == 'completed' and cycle['coverage'] == 'complete'
        tells += cycle['decision'] == 'tell'
        review = reviews.get(key)
        if review:
            known += review['correctness'] in ('correct', 'incorrect')
            if cycle.get('ended_at'):
                elapsed = (timestamp(review['recorded_at']) - timestamp(cycle['ended_at'])).total_seconds()
                if elapsed >= 0:
                    latencies.append(elapsed)
            continue
        if cycle['decision'] == 'quiet' and cycle['coverage'] == 'complete':
            quiet_seen += 1
            if (quiet_seen - 1) % quiet_every == 0:
                queue.append({'cycle_id': key, 'reason': 'quiet-sample'})
        elif cycle['decision'] == 'tell' or cycle['coverage'] != 'complete':
            queue.append({'cycle_id': key, 'reason': 'finding-or-coverage-gap'})
    days = (end - start).total_seconds() / 86400
    return {'schema_version': 1, 'window': {'start': utc_text(start), 'end': utc_text(end)},
            'observed_resources': len(resources), 'cycles': len(cycles), 'complete_cycles': complete,
            'findings': tells, 'findings_per_day': tells / days,
            'reviewed_cycles': len(reviews), 'known_correctness_cycles': known,
            'unknown_correctness_cycles': len(cycles) - known,
            'response_rate': len(reviews) / len(cycles) if cycles else None,
            'median_latest_feedback_latency_seconds': median(latencies) if latencies else None,
            'active_human_review_seconds': None,
            'review_queue': queue[:100], 'review_queue_total': len(queue), 'quiet_every': quiet_every,
            'limitations': ['Feedback latency includes waiting and corrections; it is not active review effort.',
                            'No answer or unsure correctness remains unknown.',
                            'Resource count covers retained evidence, not a complete deployment inventory.',
                            'This local review queue sends no notifications and labels no cycles.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--since', required=True)
    parser.add_argument('--until', required=True)
    parser.add_argument('--quiet-every', type=int, default=24)
    args = parser.parse_args(argv)
    journal = None
    try:
        if not (args.state / 'observer.sqlite3').is_file():
            raise ValueError('Existing observer state is required')
        from local_observe.observer.journal import Journal
        journal = Journal(args.state)
        print(json.dumps(summarize(journal, since=args.since, until=args.until, quiet_every=args.quiet_every),
                         indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError, KeyError):
        print('Feedback measurement refused; check the private state and bounded interval.', file=sys.stderr)
        return 2
    finally:
        if journal is not None:
            journal.close()


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    raise SystemExit(main())
