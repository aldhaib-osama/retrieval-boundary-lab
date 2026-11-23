# Retrieval Boundary Lab

AI-security learning lab for document-level authorization before retrieval context is built. Uses fictional principals and documents, deterministic word matching, and no LLM, embeddings or vector database. Initial code was AI-assisted.

## Run

Python 3.9+ is an intended compatibility target, not a claim of personal execution.

```sh
python retrieval_boundary.py examples/fictional.json --query 'backup recovery'
python -m unittest discover -s tests -v
```

Only the alpha document should be returned. A document from beta is denied even when user/group names overlap. Exit 0 means the query completed, including zero results. Exit 2 means invalid input. This is not an assurance verdict.

## Boundary

An exact tenant match AND an explicit user or group grant are required. Missing/malformed identity or ACL fields deny access. Empty ACLs grant nothing. Authorization runs before ranking and top-k selection. Only authorized document id/text become the simulated context. Query text cannot change identity or permissions.

## Important limits

In production, user identity, tenant and groups must come from trusted authentication and authorization services, never from client-submitted JSON. This demo fixture is not authentication. Anyone who edits the fixture can impersonate a user; do not deploy this CLI as a server or access gateway.

No cache, revocation propagation, nested groups, deny rules, ownership inheritance, audit logging, output authorization, citations, model behavior or indirect prompt-injection defense is implemented. Authorized documents can still contain malicious instructions. This lab demonstrates access isolation only, not general RAG safety. Identity comparison is case-sensitive; normalization must follow the identity provider's rules in a real system. No real documents or credentials belong in this repository. No claim is made that Dahoba has personally run or reviewed it.

Study route: GUIDE_AR.md.

Reference: security filters require application-supplied identity values and document permission metadata: https://learn.microsoft.com/en-us/azure/search/search-security-trimming-for-azure-search
