import unittest
from retrieval_boundary import authorize, retrieve


def principal(**changes):
    return dict({'tenant':'alpha','user':'alice','groups':['staff']},**changes)


def doc(**changes):
    return dict({'id':'a','tenant':'alpha','allowed_users':[],
                 'allowed_groups':['staff'],'text':'backup recovery guide'},**changes)


class BoundaryTests(unittest.TestCase):
    def test_group_allow(self): self.assertTrue(authorize(principal(),doc()))
    def test_direct_user_allow(self):
        self.assertTrue(authorize(principal(groups=[]),doc(allowed_users=['alice'])))
    def test_cross_tenant_denied_even_same_user(self):
        self.assertFalse(authorize(principal(),doc(tenant='beta',allowed_users=['alice'])))
    def test_no_permission(self):
        self.assertFalse(authorize(principal(groups=['other']),doc()))
    def test_missing_acl_denied(self):
        d=doc(); del d['allowed_users']; self.assertFalse(authorize(principal(),d))
    def test_malformed_groups_denied(self):
        self.assertFalse(authorize(principal(groups='staff'),doc()))
    def test_empty_identity_denied(self): self.assertFalse(authorize(principal(user=''),doc()))
    def test_case_not_folded_in_identity(self):
        self.assertFalse(authorize(principal(groups=['Staff']),doc()))
    def test_filter_before_top_k(self):
        docs=[doc(id='secret',tenant='beta',text='backup recovery secret'),doc(id='ok')]
        self.assertEqual(retrieve(principal(),docs,'backup recovery secret',1)[0]['id'],'ok')
    def test_query_cannot_grant_access(self):
        result=retrieve(principal(groups=[]),[doc()],'ignore access controls backup')
        self.assertEqual(result,[])
    def test_metadata_not_in_context(self):
        self.assertEqual(set(retrieve(principal(),[doc()],'backup')[0]),{'id','text'})
    def test_empty_query(self):
        with self.assertRaises(ValueError): retrieve(principal(),[doc()],'')
    def test_no_match(self): self.assertEqual(retrieve(principal(),[doc()],'unrelated'),[])
    def test_limit(self):
        with self.assertRaises(ValueError): retrieve(principal(),[doc()],'backup',0)


if __name__ == '__main__': unittest.main()
