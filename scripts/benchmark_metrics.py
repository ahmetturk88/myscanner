"""Explicit binary decision metrics; inconclusive observations never count as correct.

Callers supply independently labeled samples. A phishing-URL-derived sender is a
proxy, not verified malicious mailbox ground truth. These metrics do not change
scanner verdicts or fit thresholds to the evaluation set.
"""

POSITIVE = frozenset({'dangerous', 'review', 'malicious', 'suspicious'})
NEGATIVE = frozenset({'no_indicators', 'clean', 'harmless'})


def classification_metrics(rows):
    counts = dict(true_positive=0, false_positive=0, true_negative=0,
                  false_negative=0, inconclusive=0, invalid_target=0, errors=0)
    total = 0
    for label, verdict in rows:
        if label not in ('clean', 'threat'):
            raise ValueError('Dataset label must be clean or threat')
        total += 1
        if verdict in POSITIVE:
            counts['true_positive' if label == 'threat' else 'false_positive'] += 1
        elif verdict in NEGATIVE:
            counts['false_negative' if label == 'threat' else 'true_negative'] += 1
        else:
            counts['inconclusive'] += 1
            counts['invalid_target'] += verdict in ('invalid', 'no_domain')
            counts['errors'] += verdict in ('error', 'failed')
    decided = total - counts['inconclusive']
    def ratio(a, b):
        return round(a / b, 4) if b else None
    return dict(counts, total=total, decision_coverage=ratio(decided, total),
                precision=ratio(counts['true_positive'], counts['true_positive'] + counts['false_positive']),
                recall_among_decided=ratio(counts['true_positive'], counts['true_positive'] + counts['false_negative']),
                false_positive_rate=ratio(counts['false_positive'], counts['false_positive'] + counts['true_negative']))
