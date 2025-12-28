"""
Dashboard views - FIXED WITH SERVER ALIAS + SAFE SERVER FILTER + GEO MARKERS
"""
import logging
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q, Avg
from django.db.models.functions import TruncHour
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.db.models.functions import TruncHour, TruncMinute


from apps.logs.models import SecurityLog, ServerAlias

logger = logging.getLogger(__name__)


def _get_user_org_ids(request):
    return list(
        request.user.organization_memberships.filter(is_active=True)
        .values_list("organization_id", flat=True)
    )


def _validated_server_filter(user_org_ids, server_filter: str) -> str:
    """Only allow server filters that belong to user's orgs (prevents empty maps + avoids leakage)."""
    if not server_filter:
        return ""
    ok = ServerAlias.objects.filter(
        organization_id__in=user_org_ids,
        original_hostname=server_filter,
        is_active=True,
    ).exists()
    return server_filter if ok else ""

def _choose_step_minutes(hours: int) -> int:
    if hours <= 1:
        return 5       # 1h -> 5 min buckets (12 punkter)
    if hours <= 6:
        return 15      # 6h -> 15 min buckets (24 punkter)
    if hours <= 24:
        return 60      # 24h -> 1h buckets (24 punkter)
    if hours <= 72:
        return 180     # 3d -> 3h buckets
    return 1440        # 7d+ -> 1 dag buckets

def _floor_to_step(dt, step_minutes: int):
    dt = timezone.localtime(dt)
    if step_minutes >= 1440:
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)
    if step_minutes >= 60:
        return dt.replace(minute=0, second=0, microsecond=0)
    minute = (dt.minute // step_minutes) * step_minutes
    return dt.replace(minute=minute, second=0, microsecond=0)

@login_required
def dashboard_overview(request):
    """Main dashboard overview."""
    user_orgs = _get_user_org_ids(request)

    server_filter = request.GET.get("server", "").strip()
    server_filter = _validated_server_filter(user_orgs, server_filter)

    # Available servers (aliases) for orgs
    servers = ServerAlias.objects.filter(
        organization_id__in=user_orgs,
        is_active=True,
    ).order_by("display_name")

    # Resolve display name for selected server (org-scoped)
    current_server_display = None
    if server_filter:
        alias = servers.filter(original_hostname=server_filter).first()
        current_server_display = alias.display_name if alias else server_filter

    # Time range - last 24 hours
    time_range = timezone.now() - timedelta(hours=24)

    logs = SecurityLog.objects.filter(
        organization_id__in=user_orgs,
        timestamp__gte=time_range,
    )

    if server_filter:
        logs = logs.filter(source_host=server_filter)

    total_logs = logs.count()

    action_stats = list(
        logs.values("action")
        .annotate(count=Count("id"))
        .order_by("-count")
    )

    severity_stats = list(
        logs.values("severity")
        .annotate(count=Count("id"))
        .order_by("-count")
    )

    source_stats = list(
        logs.values("source_type")
        .annotate(count=Count("id"))
        .order_by("-count")
    )

    top_ips = (
        logs.values("src_ip")
        .annotate(count=Count("id"))
        .order_by("-count")[:10]
    )

    recent_logs = logs.order_by("-timestamp")[:20]

    critical_count = logs.filter(severity__in=["critical", "high"]).count()
    blocked_count = logs.filter(action__in=["deny", "ban", "rate_limit"]).count()

    context = {
        "total_logs": total_logs,
        "action_stats": action_stats,
        "severity_stats": severity_stats,
        "source_stats": source_stats,
        "top_ips": top_ips,
        "recent_logs": recent_logs,
        "critical_count": critical_count,
        "blocked_count": blocked_count,
        "time_range_hours": 24,
        "servers": servers,
        "current_server": server_filter,  # IMPORTANT: hostname string
        "current_server_display": current_server_display,
    }
    return render(request, "dashboard/overview.html", context)


@login_required
def recent_logs_partial(request):
    user_orgs = _get_user_org_ids(request)

    server_filter = request.GET.get("server", "").strip()
    server_filter = _validated_server_filter(user_orgs, server_filter)

    logs = SecurityLog.objects.filter(organization_id__in=user_orgs)

    if server_filter:
        logs = logs.filter(source_host=server_filter)

    recent_logs = logs.order_by("-timestamp")[:20]

    return render(
        request,
        "dashboard/partials/recent_logs.html",
        {"recent_logs": recent_logs},
    )


@login_required
def stats_partial(request):
    user_orgs = _get_user_org_ids(request)

    server_filter = request.GET.get("server", "").strip()
    server_filter = _validated_server_filter(user_orgs, server_filter)

    time_range = timezone.now() - timedelta(hours=24)

    logs = SecurityLog.objects.filter(
        organization_id__in=user_orgs,
        timestamp__gte=time_range,
    )

    if server_filter:
        logs = logs.filter(source_host=server_filter)

    total_logs = logs.count()
    critical_count = logs.filter(severity__in=["critical", "high"]).count()
    blocked_count = logs.filter(action__in=["deny", "ban", "rate_limit"]).count()
    unique_ips = logs.values("src_ip").distinct().count()

    return render(
        request,
        "dashboard/partials/stats.html",
        {
            "total_logs": total_logs,
            "critical_count": critical_count,
            "blocked_count": blocked_count,
            "unique_ips": unique_ips,
        },
    )

@login_required
def timeline_data(request):
    hours = int(request.GET.get("hours", 24))
    now = timezone.now()
    time_range = now - timedelta(hours=hours)

    user_orgs = _get_user_org_ids(request)

    server_filter = (request.GET.get("server") or "").strip()
    server_filter = _validated_server_filter(user_orgs, server_filter)

    logs = SecurityLog.objects.filter(
        organization_id__in=user_orgs,
        timestamp__gte=time_range,
        timestamp__lte=now,
    )
    if server_filter:
        logs = logs.filter(source_host=server_filter)

    # Auto bucket-size för "live-känsla"
    if hours <= 1:
        bucket_minutes = 1
    elif hours <= 6:
        bucket_minutes = 5
    elif hours <= 24:
        bucket_minutes = 15
    elif hours <= 72:
        bucket_minutes = 60
    else:
        bucket_minutes = 120  # 2h

    tz = timezone.get_current_timezone()
    severity_keys = ["low", "medium", "high", "critical"]

    labels = []
    total = []
    by_severity = {k: [] for k in severity_keys}

    # --- <= 24h: minute-granular data, bucket:as i Python (1/5/15 min) ---
    if bucket_minutes < 60:
        rows = (
            logs.annotate(t=TruncMinute("timestamp", tzinfo=tz))
            .values("t", "severity")
            .annotate(count=Count("id"))
        )

        # dict: (datetime_minute, severity) -> count
        minute_counts = {(r["t"], r["severity"]): r["count"] for r in rows}

        start = time_range.astimezone(tz).replace(second=0, microsecond=0)
        end = now.astimezone(tz).replace(second=0, microsecond=0)

        # align start till närmsta bucket-gräns
        start = start - timedelta(minutes=(start.minute % bucket_minutes))

        step = timedelta(minutes=bucket_minutes)
        while start <= end:
            bucket_total = 0
            bucket_sev = {k: 0 for k in severity_keys}

            # summera alla minuter i bucket:t
            t = start
            for _ in range(bucket_minutes):
                for sev in severity_keys:
                    c = minute_counts.get((t, sev), 0)
                    bucket_sev[sev] += c
                    bucket_total += c
                t += timedelta(minutes=1)

            # label-format
            if hours <= 24:
                label = start.strftime("%H:%M")
            else:
                label = start.strftime("%m/%d %H:%M")

            labels.append(label)
            total.append(bucket_total)
            for sev in severity_keys:
                by_severity[sev].append(bucket_sev[sev])

            start += step

    # --- > 24h: hour-granular data, bucket:as i 1h/2h ---
    else:
        rows = (
            logs.annotate(t=TruncHour("timestamp", tzinfo=tz))
            .values("t", "severity")
            .annotate(count=Count("id"))
        )

        hour_counts = {(r["t"], r["severity"]): r["count"] for r in rows}

        start = time_range.astimezone(tz).replace(minute=0, second=0, microsecond=0)
        end = now.astimezone(tz).replace(minute=0, second=0, microsecond=0)

        bucket_hours = bucket_minutes // 60
        step = timedelta(hours=bucket_hours)

        while start <= end:
            bucket_total = 0
            bucket_sev = {k: 0 for k in severity_keys}

            t = start
            for _ in range(bucket_hours):
                for sev in severity_keys:
                    c = hour_counts.get((t, sev), 0)
                    bucket_sev[sev] += c
                    bucket_total += c
                t += timedelta(hours=1)

            label = start.strftime("%m/%d %H:00")
            labels.append(label)
            total.append(bucket_total)
            for sev in severity_keys:
                by_severity[sev].append(bucket_sev[sev])

            start += step

    return JsonResponse({"labels": labels, "total": total, "by_severity": by_severity})


def country_code_to_flag(code: str) -> str:
    if not code:
        return "🌍"
    code = code.strip().upper()
    if len(code) != 2 or not code.isalpha():
        return "🌍"
    return chr(0x1F1E6 + (ord(code[0]) - 65)) + chr(0x1F1E6 + (ord(code[1]) - 65))


@login_required
def geographic_data(request):
    user_orgs = _get_user_org_ids(request)

    hours = int(request.GET.get("hours", 24))
    time_range = timezone.now() - timedelta(hours=hours)

    server_filter = (request.GET.get("server") or "").strip()
    server_filter = _validated_server_filter(user_orgs, server_filter)

    logs = SecurityLog.objects.filter(
        organization_id__in=user_orgs,
        timestamp__gte=time_range,
    )

    if server_filter:
        logs = logs.filter(source_host=server_filter)

    logs = logs.filter(
        Q(geo_enriched=True) | (Q(latitude__isnull=False) & Q(longitude__isnull=False))
    ).exclude(country_code__in=["XX", "LAN"])

    logs = logs.filter(latitude__isnull=False, longitude__isnull=False)

    countries = logs.values("country_code", "country_name").annotate(
        count=Count("id"),
        avg_lat=Avg("latitude"),
        avg_lon=Avg("longitude"),
    ).order_by("-count")

    max_count = countries[0]["count"] if countries else 0
    threshold_high = max_count * 0.75
    threshold_medium = max_count * 0.50
    threshold_low = max_count * 0.25

    markers = []
    for c in countries:
        lat = c["avg_lat"]
        lon = c["avg_lon"]
        if lat is None or lon is None:
            continue

        count = c["count"]
        if count >= threshold_high:
            color = "#ef4444"
        elif count >= threshold_medium:
            color = "#f97316"
        elif count >= threshold_low:
            color = "#eab308"
        else:
            color = "#3b82f6"

        cc = (c["country_code"] or "").upper()
        markers.append({
            "country_code": cc,
            "country_name": c["country_name"] or "Unknown",
            "lat": float(lat),
            "lon": float(lon),
            "count": count,
            "color": color,
            "flag": country_code_to_flag(cc),
        })

    return JsonResponse({
        "markers": markers,
        "top_countries": list(countries[:10]),
        "total_countries": len(markers),
        "total_attacks": logs.count(),
        "server_filter": server_filter,  # bra för debug i console
    })

@login_required
def isp_stats_data(request):
    """API endpoint for ISP/ASN statistics."""
    user_orgs = _get_user_org_ids(request)

    hours = int(request.GET.get("hours", 24))
    time_range = timezone.now() - timedelta(hours=hours)

    server_filter = (request.GET.get("server") or "").strip()
    server_filter = _validated_server_filter(user_orgs, server_filter)

    logs = SecurityLog.objects.filter(
        organization_id__in=user_orgs,
        timestamp__gte=time_range,
    )

    if server_filter:
        logs = logs.filter(source_host=server_filter)

    # ISP-data: acceptera om isp inte är null/blank och exkludera "LAN/XX"
    logs = logs.exclude(Q(country_code__in=["XX", "LAN"]) | Q(country_code__isnull=True))
    logs = logs.exclude(Q(isp__isnull=True) | Q(isp=""))

    isps = (
        logs.values("isp", "asn")
        .annotate(count=Count("id"))
        .order_by("-count")[:10]
    )

    return JsonResponse({
        "top_isps": list(isps),
        "total_with_isp": logs.count(),
        "server_filter": server_filter,
    })
