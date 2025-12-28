# apps/core/views.py
import logging
import os
import requests

from datetime import timedelta
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.generic import TemplateView
from django.core.cache import cache

from apps.logs.models import SecurityLog, ServerAlias
from apps.organizations.models import Organization, OrganizationMember

from .forms import JoinRequestForm
from .models import JoinRequest

logger = logging.getLogger(__name__)


def health_check(_request):
    return JsonResponse({"status": "ok"})

def home(request):
    return redirect("dashboard:overview") if request.user.is_authenticated else redirect("landing")

def _get_client_ip(request):
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")

def _notify_discord(join_req: JoinRequest):
    webhook = os.getenv("REQUEST_JOIN", "").strip()
    if not webhook:
        return

    content = (
        f"**New Request to Join**\n"
        f"Email: `{join_req.email}`\n"
        f"Name: {join_req.full_name or '-'}\n"
        f"Company: {join_req.company or '-'}\n"
        f"Message: {join_req.message or '-'}\n"
        f"IP: `{join_req.ip_address or '-'}`"
    )
    # keep it simple; if it fails we just skip
    try:
        requests.post(webhook, json={"content": content}, timeout=5).raise_for_status()
    except Exception:
        pass

def request_join(request):
    # basic IP rate limit: 1 request / 60s per IP
    ip = _get_client_ip(request)
    rl_key = f"joinreq-ip:{ip}"
    if request.method == "POST" and cache.get(rl_key):
        messages.error(request, "Too many requests. Try again in a minute.")
        return redirect("core:request_join")

    if request.method == "POST":
        form = JoinRequestForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"].lower().strip()

            # 1 pending request per email (no spam)
            if JoinRequest.objects.filter(email=email, status=JoinRequest.Status.PENDING).exists():
                messages.info(request, "You already have a pending request. We’ll get back to you.")
                return redirect("core:request_join")

            jr = JoinRequest.objects.create(
                email=email,
                full_name=form.cleaned_data.get("full_name", "").strip(),
                company=form.cleaned_data.get("company", "").strip(),
                message=form.cleaned_data.get("message", "").strip(),
                ip_address=ip,
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                created_at=timezone.now(),
            )

            cache.set(rl_key, True, timeout=60)
            _notify_discord(jr)

            messages.success(request, "Request submitted! We’ll review it and get back to you.")
            return redirect("request_join")
    else:
        form = JoinRequestForm()

    return render(request, "core/request_join.html", {"form": form})


class LandingPageView(TemplateView):
    template_name = "core/landing.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["stats"] = {
            "organizations": Organization.objects.count(),
            "servers": ServerAlias.objects.count(),
            "threats_blocked": SecurityLog.objects.filter(
                action="blocked",
                timestamp__gte=timezone.now() - timedelta(days=30),
            ).count(),
            "uptime": 99.9,
            "response_time": 50,
        }
        return context


def get_client_ip(request) -> str:
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def get_user_organization(user):
    member = (
        OrganizationMember.objects.filter(user=user)
        .select_related("organization")
        .first()
    )
    return member.organization if member else None


@ensure_csrf_cookie
def custom_login_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard:overview")

    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        ip_address = get_client_ip(request)

        if form.is_valid():
            user = form.get_user()
            login(request, user)
            messages.success(request, f"Welcome back, {user.get_username()}!")

            org = get_user_organization(user)

            # Only log if org exists (organization is NOT NULL)
            if org:
                try:
                    SecurityLog.objects.create(
                        organization=org,
                        source_type="auth",
                        source_host=request.get_host(),
                        timestamp=timezone.now(),
                        src_ip=ip_address,
                        user_agent=request.META.get("HTTP_USER_AGENT", ""),
                        action="login_success",
                        severity="low",
                        reason=f"User {user.get_username()} authenticated successfully",
                        raw_log=f"login_success user={user.get_username()} ip={ip_address}",
                        metadata={"event": "login_success", "user_id": user.pk},
                    )
                except Exception as e:
                    logger.warning("Could not create login_success SecurityLog: %s", e)

            # Remember me
            if not request.POST.get("remember_me"):
                request.session.set_expiry(0)

            # Redirect next or dashboard overview (same for all users)
            next_url = request.GET.get("next")
            return redirect(next_url or "dashboard:overview")

        messages.error(request, "Invalid username or password.")
        logger.warning(
            "Failed login attempt username=%s ip=%s",
            request.POST.get("username", ""),
            ip_address,
        )

    else:
        form = AuthenticationForm()

    return render(request, "registration/login.html", {"form": form})


@login_required
def dashboard_redirect(request):
    # Always send everyone to the dashboard overview.
    return redirect("dashboard:overview")
