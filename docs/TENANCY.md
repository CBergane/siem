# Multi-Tenancy

This app is multi-tenant. Data is scoped to an `Organization` and access is granted via memberships.

## Organization
- Top-level tenant boundary for data and access control.
- API keys are tied to an organization and used for ingest endpoints.

## Membership roles
- `owner`: full access; can manage users and API keys.
- `admin`: same as owner for day-to-day management.
- `analyst`: can create alerts and export data.
- `readonly`: view-only access.

## Org scoping
- Requests that use API keys are scoped to the API key's organization.
- UI actions are scoped to the organization linked to the authenticated user.
- Cross-org access is not allowed.
