"""Read the real notification policy, without pretending findings are sends."""
from local_observe.platform.notification_safety import NotificationPolicy


def enforced_limits(policy=None):
    policy = policy or NotificationPolicy()
    return {'channel': policy.channel, 'max_attempts': policy.max_attempts,
            'window_seconds': policy.window_seconds, 'delivery_mode': policy.delivery_mode,
            'latches_on_exhaustion': True, 'reset_required': True,
            'findings_per_day_ceiling': None, 'precision_floor': None,
            'limit': 'Attempts per channel rolling window; breaker stays latched until explicit reset. '
                     'Findings are not sends. Human resets prevent deriving a daily send ceiling.'}
