from __future__ import annotations


GRAPHQL_CANDIDATE_PATHS = ["/graphql", "/api/graphql", "/gql"]


def looks_like_graphql_response(text: str) -> bool:
    lowered = text.lower()
    return "graphql" in lowered or '"errors"' in lowered or '"data"' in lowered

