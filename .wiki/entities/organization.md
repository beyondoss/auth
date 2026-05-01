---
kind: entity
title: Organization
summary: Group of users with roles, members, and invitations; auto-created as personal org per user.
sources:
  - .wiki/sources/2026-04-30-auth-service-overview.md
  - .wiki/sources/2026-04-30-auth-architecture.md
links:
  - entities/user.md
last_verified_at: 2026-04-30
---

## Overview

Organizations (orgs) group users with roles and permissions. Every user has a **personal org** created automatically at signup—always present, never deletable.

Users can create additional **team orgs**, invite members, and assign roles.

## Personal Org

Auto-created 1:1 with each user at signup. Cannot be deleted. Serves as the user's default context for resources.

## Team Org

Created explicitly via the API. Has members and invitations. Supports role-based membership.

## Members and Roles

Users can be members of an org with a role. Roles are application-defined; the auth service stores and enforces them. Typical roles: `admin`, `member`, `viewer`.

## Invitations

Pending membership is represented by an invitation token (`inv` prefix, 7-day TTL):

1. `POST /v1/orgs/{id}/invitations` — send an invite to an email
2. Email contains link with token
3. `POST /v1/invitations/{id}/accept` — accept the invite, joining the org

## Changelog

- 2026-04-30: Extracted from auth-readme and auth-architecture raw sources
