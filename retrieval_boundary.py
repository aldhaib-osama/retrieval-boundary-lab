"""Offline retrieval access-control simulation. No model or vector database."""
import argparse
import json


def valid_strings(value):
    return isinstance(value, list) and all(isinstance(x,str) and x.strip() for x in value)


def authorize(principal, document):
    # The caller must obtain principal identity from a trusted authentication layer.
    # This demo reads fictional fixture principals only.
    tenant = principal.get('tenant'); user = principal.get('user')
    groups = principal.get('groups')
    if not isinstance(tenant,str) or not tenant.strip() or not isinstance(user,str) or not user.strip():
        return False
    if not valid_strings(groups): return False
    if document.get('tenant') != tenant: return False
    allowed_users = document.get('allowed_users'); allowed_groups = document.get('allowed_groups')
    if not valid_strings(allowed_users) or not valid_strings(allowed_groups): return False
    return user in allowed_users or bool(set(groups) & set(allowed_groups))


def retrieve(principal, documents, query, limit=3):
    if type(limit) is not int or limit < 1: raise ValueError('limit must be positive')
    if not isinstance(query,str) or not query.strip(): raise ValueError('query must be nonempty')
    if not isinstance(documents,list): raise ValueError('documents must be a list')
    words = set(query.casefold().split()); ranked=[]
    for doc in documents:
        if not isinstance(doc,dict): raise ValueError('document must be an object')
        # Filter BEFORE ranking or building model context.
        if not authorize(principal,doc): continue
        if not isinstance(doc.get('text'),str) or not isinstance(doc.get('id'),str):
            raise ValueError('Authorized document needs id and text')
        score=len(words & set(doc['text'].casefold().split()))
        if score: ranked.append((score,doc['id'],doc['text']))
    ranked.sort(key=lambda row:(-row[0],row[1]))
    return [{'id':ident,'text':text} for score,ident,text in ranked[:limit]]


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixture'); parser.add_argument('--query',required=True)
    args=parser.parse_args(argv)
    try:
        with open(args.fixture,encoding='utf-8') as f: data=json.load(f)
        if not isinstance(data,dict) or not isinstance(data.get('principal'),dict):
            raise ValueError('Expected fictional principal and documents')
        result=retrieve(data['principal'],data.get('documents'),args.query)
        print(json.dumps({'retrieved':result},indent=2))
        return 0
    except (OSError,ValueError,TypeError) as error:
        parser.exit(2,f'Input error: {error}\n')


if __name__ == '__main__': raise SystemExit(main())
