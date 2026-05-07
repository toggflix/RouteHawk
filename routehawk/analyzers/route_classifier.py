from __future__ import annotations

from typing import List


KEYWORD_TAGS = {
    "admin": {"admin", "administrator", "superuser"},
    "internal": {"internal", "private", "staff"},
    "debug": {"debug", "trace", "metrics", "health", "config"},
    "object-reference": {"{id}", "{uuid}", "{hash}", "{token}", "{email}"},
    "billing": {"billing", "invoice", "invoices", "payment", "payments", "subscription"},
    "auth": {"login", "logout", "oauth", "token", "session", "sso"},
    "account-recovery": {"reset-password", "forgot-password", "password-reset"},
    "data-export": {"export", "download", "report"},
    "data-import": {"import", "upload"},
    "authorization": {"role", "roles", "permission", "permissions", "policy", "policies"},
    "user-object": {"user", "users", "account", "accounts", "customer", "customers", "profile"},
    "business-object": {"order", "orders", "project", "projects", "tenant", "tenants"},
    "graphql": {"graphql", "gql"},
}


def classify_endpoint(method: str, normalized_path: str) -> List[str]:
    del method
    lowered = normalized_path.lower()
    tokens = {token for token in lowered.replace("_", "-").split("/") if token}
    tags = []

    for tag, keywords in KEYWORD_TAGS.items():
        if any(keyword in tokens or keyword in lowered for keyword in keywords):
            tags.append(tag)

    return sorted(set(tags))
