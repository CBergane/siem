from django.utils import timezone
from datetime import timedelta
from apps.alerts.models import AlertRule
from apps.logs.models import SecurityLog

def debug_alert_rules():
    rules = AlertRule.objects.filter(enabled=True)
    print("Rules:", rules.count())

    for rule in rules:
        print("----")
        print("Rule:", rule.id, rule.name, "org:", rule.organization_id)
        print("threshold:", rule.threshold, "time_window:", rule.time_window_minutes)
        print("filters:", rule.source_type, rule.action, rule.severity, rule.country_code, rule.ip_address)

        window_start = timezone.now() - timedelta(minutes=rule.time_window_minutes)

        qs = SecurityLog.objects.filter(
            organization=rule.organization,
            timestamp__gte=window_start,
        )

        if rule.source_type:
            qs = qs.filter(source_type=rule.source_type)
        if rule.action:
            qs = qs.filter(action=rule.action)
        if rule.severity:
            qs = qs.filter(severity=rule.severity)
        if rule.country_code:
            qs = qs.filter(country_code=rule.country_code)
        if rule.ip_address:
            qs = qs.filter(src_ip=rule.ip_address)

        print("Matched events:", qs.count())

debug_alert_rules()
