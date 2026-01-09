"""
Dashboard views - FIXED WITH SERVER ALIAS + SAFE SERVER FILTER + GEO MARKERS
"""
import json
import logging
import re
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Count, Q, Avg, OuterRef, Subquery
from django.db.models.functions import TruncHour
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.db.models.functions import TruncHour, TruncMinute


from apps.logs.models import SecurityLog, ServerAlias, InventorySnapshot

logger = logging.getLogger(__name__)


def _get_user_org_ids(request):
    if request.user.is_superuser:
        from apps.organizations.models import Organization
        return list(Organization.objects.values_list("id", flat=True))
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

SENSITIVE_KEY_PATTERN = re.compile(
    r"(password|secret|token|api_key|private_key|authorization|cookie|env_vars|environment_variables|\benv\b)",
    re.IGNORECASE,
)
JWT_PATTERN = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
HEX_PATTERN = re.compile(r"^[A-Fa-f0-9]{32,}$")


def _looks_sensitive_value(value: str) -> bool:
    if "-----BEGIN " in value or "PRIVATE KEY-----" in value:
        return True
    if JWT_PATTERN.match(value):
        return True
    if HEX_PATTERN.match(value):
        return True
    return False


def sanitize_inventory_payload(payload):
    if isinstance(payload, dict):
        sanitized = {}
        for key, value in payload.items():
            if SENSITIVE_KEY_PATTERN.search(str(key)):
                sanitized[key] = "[redacted]"
                continue
            sanitized[key] = sanitize_inventory_payload(value)
        return sanitized
    if isinstance(payload, list):
        return [sanitize_inventory_payload(item) for item in payload]
    if isinstance(payload, str) and _looks_sensitive_value(payload):
        return "[redacted]"
    return payload


def safe_get(payload, path, default=None):
    current = payload
    for key in path:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current


def _format_bytes(value):
    if value is None:
        return None
    try:
        size = float(value)
    except (TypeError, ValueError):
        return None
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024
        idx += 1
    if idx == 0:
        return f"{int(size)} {units[idx]}"
    return f"{size:.1f} {units[idx]}"


def _format_uptime(seconds):
    if seconds is None:
        return None
    try:
        total = int(float(seconds))
    except (TypeError, ValueError):
        return None
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or (days and minutes):
        parts.append(f"{hours}h")
    if not days and minutes:
        parts.append(f"{minutes}m")
    if not parts:
        parts.append("0m")
    return " ".join(parts)


def extract_inventory_summary(payload):
    summary = {}

    os_value = payload.get("os")
    if isinstance(os_value, dict):
        os_name = os_value.get("pretty_name") or os_value.get("name") or os_value.get("distro")
        os_version = os_value.get("version") or os_value.get("version_id")
        os_display = " ".join([v for v in [os_name, os_version] if v])
    elif isinstance(os_value, str):
        os_display = os_value
    else:
        os_display = None

    kernel = payload.get("kernel") or safe_get(payload, ["os", "kernel"])
    uptime_display = _format_uptime(payload.get("uptime_seconds"))

    cpu_model = payload.get("cpu_model") or safe_get(payload, ["cpu", "model"])
    cpu_count = payload.get("vcpu_count") or payload.get("cpu_count") or safe_get(payload, ["cpu", "count"])

    ram_total = None
    ram_mb = payload.get("ram_total_mb") or safe_get(payload, ["memory", "total_mb"])
    ram_bytes = payload.get("ram_total_bytes") or safe_get(payload, ["memory", "total_bytes"])
    if ram_mb is not None:
        ram_total = _format_bytes(float(ram_mb) * 1024 * 1024)
    elif ram_bytes is not None:
        ram_total = _format_bytes(ram_bytes)

    disk_count = None
    disk_total = None
    disk_list = payload.get("disks")
    if isinstance(disk_list, list) and disk_list:
        disk_count = len(disk_list)
        total_bytes = 0.0
        has_size = False
        for disk in disk_list:
            if not isinstance(disk, dict):
                continue
            size_bytes = disk.get("size_bytes")
            size_gb = disk.get("size_gb")
            if size_bytes is not None:
                total_bytes += float(size_bytes)
                has_size = True
            elif size_gb is not None:
                total_bytes += float(size_gb) * 1024 * 1024 * 1024
                has_size = True
        if has_size:
            disk_total = _format_bytes(total_bytes)
    else:
        disk_count = payload.get("disk_count")
        disk_total = payload.get("disk_total") or payload.get("disk_total_gb") or payload.get("disk_total_bytes")
        if disk_total is not None:
            if isinstance(disk_total, (int, float)) and disk_total > 1024:
                disk_total = _format_bytes(disk_total)
            else:
                try:
                    disk_total = _format_bytes(float(disk_total) * 1024 * 1024 * 1024)
                except (TypeError, ValueError):
                    disk_total = None

    public_ips = payload.get("public_ips")
    if isinstance(public_ips, str):
        public_ips = [public_ips]
    if not public_ips:
        public_ip = payload.get("public_ip")
        if public_ip:
            public_ips = [public_ip]
    if public_ips and not isinstance(public_ips, list):
        public_ips = None

    containers = payload.get("containers")
    containers_count = None
    containers_top = []
    if isinstance(containers, list):
        containers_count = len(containers)
        for item in containers[:3]:
            if not isinstance(item, dict):
                continue
            name = item.get("name") or item.get("container")
            runtime = item.get("runtime")
            image = item.get("image")
            label = name or image
            if not label:
                continue
            if runtime:
                label = f"{label} ({runtime})"
            containers_top.append(label)

    services = payload.get("services")
    services_total = None
    services_active = None
    services_top = []
    if isinstance(services, list):
        services_total = len(services)
        services_active = 0
        for item in services:
            if not isinstance(item, dict):
                continue
            state = str(item.get("state") or "").lower()
            if state == "active" or item.get("active") is True:
                services_active += 1
        for item in services[:5]:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if name:
                services_top.append(name)

    ports = payload.get("listening_ports") or payload.get("ports")
    ports_count = None
    ports_top = []
    if isinstance(ports, list):
        ports_count = len(ports)
        for item in ports[:10]:
            if not isinstance(item, dict):
                continue
            port = item.get("port") or item.get("port_number")
            proto = item.get("proto") or item.get("protocol")
            process = item.get("process") or item.get("name")
            if port is None:
                continue
            label = f"{port}"
            if proto:
                label = f"{label}/{proto}"
            if process:
                label = f"{label} ({process})"
            ports_top.append(label)

    updates = payload.get("updates") or {}
    updates_security = None
    updates_packages = None
    if isinstance(updates, dict):
        updates_security = updates.get("security")
        updates_packages = updates.get("packages") or updates.get("count")

    summary.update({
        "os": os_display,
        "kernel": kernel,
        "uptime": uptime_display,
        "cpu_model": cpu_model,
        "cpu_count": cpu_count,
        "ram_total": ram_total,
        "disk_count": disk_count,
        "disk_total": disk_total,
        "public_ips": public_ips,
        "containers_count": containers_count,
        "containers_top": containers_top,
        "services_total": services_total,
        "services_active": services_active,
        "services_top": services_top,
        "ports_count": ports_count,
        "ports_top": ports_top,
        "updates_security": updates_security,
        "updates_packages": updates_packages,
    })

    return summary

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
def inventory_overview(request):
    user_orgs = _get_user_org_ids(request)

    server_filter = (request.GET.get("server") or "").strip()
    server_filter = _validated_server_filter(user_orgs, server_filter)

    history_mode = bool(server_filter)
    default_hours = 24 if history_mode else 168

    hours_raw = request.GET.get("hours", str(default_hours))
    try:
        hours = int(hours_raw)
    except (TypeError, ValueError):
        hours = default_hours
    if hours <= 0:
        hours = default_hours
    if hours > 720:
        hours = 720

    servers = ServerAlias.objects.filter(
        organization_id__in=user_orgs,
        is_active=True,
    ).order_by("display_name")

    current_server_display = None
    if server_filter:
        alias = servers.filter(original_hostname=server_filter).first()
        current_server_display = alias.display_name if alias else server_filter

    server_options = []
    for alias in servers:
        server_options.append({"value": alias.original_hostname, "label": alias.display_name})

    time_range = timezone.now() - timedelta(hours=hours)
    base_qs = InventorySnapshot.objects.filter(
        organization_id__in=user_orgs,
        created_at__gte=time_range,
    ).select_related("organization").order_by("-created_at")

    if history_mode:
        snapshots_qs = base_qs.filter(source_host=server_filter).order_by("-created_at")
        paginator = Paginator(snapshots_qs, 50)
        page_obj = paginator.get_page(request.GET.get("page"))
        snapshots = list(page_obj.object_list)
    else:
        latest_id_per_server = base_qs.filter(
            source_host=OuterRef("source_host")
        ).order_by("-created_at").values("id")[:1]
        snapshots = list(
            base_qs.filter(id=Subquery(latest_id_per_server))
            .order_by("-created_at")[:200]
        )
        page_obj = None

    inventory_items = []
    for snapshot in snapshots:
        payload = snapshot.payload or {}
        summary = extract_inventory_summary(payload)
        sanitized = sanitize_inventory_payload(payload)
        payload_pretty = json.dumps(sanitized, indent=2, sort_keys=True)
        inventory_items.append({
            "snapshot": snapshot,
            "summary": summary,
            "payload_pretty": payload_pretty,
        })

    context = {
        "inventory_items": inventory_items,
        "hours": hours,
        "hours_options": [24, 72, 168],
        "history_mode": history_mode,
        "page_obj": page_obj,
        "current_server": server_filter,
        "current_server_display": current_server_display,
        "server_options": server_options,
    }
    return render(request, "dashboard/inventory.html", context)


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

    top_countries = []
    for c in countries[:10]:
        cc = (c["country_code"] or "").upper()
        top_countries.append({
            "country_code": cc,
            "country_name": c["country_name"] or "Unknown",
            "count": c["count"],
            "flag": country_code_to_flag(cc),
        })

    return JsonResponse({
        "markers": markers,
        "top_countries": top_countries,
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
