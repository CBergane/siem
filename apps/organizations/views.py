import json

from django.contrib import messages
from django.http import HttpResponseForbidden
from django.shortcuts import render, redirect

from apps.organizations.models import APIKey, Agent, Organization, OrganizationMember


def _allowed_orgs(user):
    if user.is_superuser:
        return Organization.objects.all()
    return Organization.objects.filter(members__user=user, members__is_active=True).distinct()


def _resolve_org(request):
    orgs = _allowed_orgs(request.user)
    slug = request.GET.get("org", "").strip()

    if slug:
        if request.user.is_superuser:
            org = Organization.objects.filter(slug=slug).first()
        else:
            org = orgs.filter(slug=slug).first()
        if not org:
            return None, HttpResponseForbidden("Forbidden")
        return org, None

    if not request.user.is_superuser and orgs.count() == 0:
        return None, HttpResponseForbidden("Forbidden")

    if orgs.count() == 1:
        return orgs.first(), None

    return None, render(
        request,
        "organizations/org_select.html",
        {"orgs": orgs.order_by("name"), "path": request.path},
    )


def _get_membership(user, org):
    return OrganizationMember.objects.filter(
        organization=org,
        user=user,
        is_active=True,
    ).first()


def _can_manage(user, membership):
    if user.is_superuser:
        return True
    return membership and membership.role in {"owner", "admin"}


def org_keys(request):
    if not request.user.is_authenticated:
        return redirect("login")

    org, response = _resolve_org(request)
    if response:
        return response

    membership = _get_membership(request.user, org)
    if not membership and not request.user.is_superuser:
        return HttpResponseForbidden("Forbidden")

    can_manage = _can_manage(request.user, membership)

    if request.method == "POST":
        if not can_manage:
            return HttpResponseForbidden("Forbidden")

        action = request.POST.get("action")
        if action == "create":
            name = request.POST.get("name", "").strip() or "API Key"
            plain_key = APIKey.generate_key()
            api_key = APIKey(organization=org, name=name)
            api_key.encrypt_key(plain_key)
            api_key.save()
            request.session["created_api_key"] = {"org": org.slug, "key": plain_key}
        elif action == "toggle":
            key_id = request.POST.get("key_id")
            api_key = APIKey.objects.filter(id=key_id, organization=org).first()
            if api_key:
                api_key.is_active = not api_key.is_active
                api_key.save(update_fields=["is_active"])
        return redirect(f"{request.path}?org={org.slug}")

    created_key = None
    session_key = request.session.pop("created_api_key", None)
    if session_key and session_key.get("org") == org.slug:
        created_key = session_key.get("key")

    keys = APIKey.objects.filter(organization=org).order_by("-created_at")
    return render(
        request,
        "organizations/org_keys.html",
        {
            "org": org,
            "keys": keys,
            "created_key": created_key,
            "can_manage": can_manage,
        },
    )


def org_agents(request):
    if not request.user.is_authenticated:
        return redirect("login")

    org, response = _resolve_org(request)
    if response:
        return response

    membership = _get_membership(request.user, org)
    if not membership and not request.user.is_superuser:
        return HttpResponseForbidden("Forbidden")

    can_manage = _can_manage(request.user, membership)

    if request.method == "POST":
        if not can_manage:
            return HttpResponseForbidden("Forbidden")

        action = request.POST.get("action")
        if action == "create":
            agent_id = request.POST.get("agent_id", "").strip()
            metadata_raw = request.POST.get("metadata", "").strip()
            is_active = request.POST.get("is_active") == "1"
            if not agent_id:
                messages.error(request, "Agent ID is required.")
                return redirect(f"{request.path}?org={org.slug}")
            metadata = {}
            if metadata_raw:
                try:
                    metadata = json.loads(metadata_raw)
                except json.JSONDecodeError:
                    messages.error(request, "Metadata must be valid JSON.")
                    return redirect(f"{request.path}?org={org.slug}")
            plain_secret = Agent.generate_secret()
            agent = Agent(
                agent_id=agent_id,
                organization=org,
                metadata=metadata,
                is_active=is_active,
            )
            agent.set_secret(plain_secret)
            agent.save()
            request.session["created_agent_secret"] = {
                "org": org.slug,
                "agent_id": agent.agent_id,
                "secret": plain_secret,
            }
        elif action == "toggle":
            agent_id = request.POST.get("agent_id")
            agent = Agent.objects.filter(agent_id=agent_id, organization=org).first()
            if agent:
                agent.is_active = not agent.is_active
                agent.save(update_fields=["is_active"])
        elif action == "rotate":
            agent_id = request.POST.get("agent_id")
            agent = Agent.objects.filter(agent_id=agent_id, organization=org).first()
            if agent:
                plain_secret = Agent.generate_secret()
                agent.set_secret(plain_secret)
                agent.save(update_fields=["secret_hash", "secret_prefix", "secret_created_at"])
                request.session["created_agent_secret"] = {
                    "org": org.slug,
                    "agent_id": agent.agent_id,
                    "secret": plain_secret,
                }
        return redirect(f"{request.path}?org={org.slug}")

    created_agent_secret = None
    session_secret = request.session.pop("created_agent_secret", None)
    if session_secret and session_secret.get("org") == org.slug:
        created_agent_secret = session_secret

    agents = Agent.objects.filter(organization=org).order_by("agent_id")
    base_url = request.build_absolute_uri("/").rstrip("/")
    api_key = APIKey.objects.filter(organization=org, is_active=True).order_by("-created_at").first()
    agent = agents.filter(is_active=True).first()
    return render(
        request,
        "organizations/org_agents.html",
        {
            "org": org,
            "agents": agents,
            "can_manage": can_manage,
            "created_agent_secret": created_agent_secret,
            "base_url": base_url,
            "api_key": api_key,
            "agent": agent,
        },
    )


def org_install(request):
    if not request.user.is_authenticated:
        return redirect("login")

    org, response = _resolve_org(request)
    if response:
        return response

    membership = _get_membership(request.user, org)
    if not membership and not request.user.is_superuser:
        return HttpResponseForbidden("Forbidden")

    api_key = APIKey.objects.filter(organization=org, is_active=True).order_by("-created_at").first()
    agent = Agent.objects.filter(organization=org, is_active=True).order_by("agent_id").first()
    base_url = request.build_absolute_uri("/").rstrip("/")

    return render(
        request,
        "organizations/org_install.html",
        {
            "org": org,
            "api_key": api_key,
            "agent": agent,
            "base_url": base_url,
        },
    )
