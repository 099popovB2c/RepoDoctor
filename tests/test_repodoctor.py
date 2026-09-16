import unittest,tempfile,pathlib,sys
sys.path.insert(0,str(pathlib.Path(__file__).parents[1]));import repodoctor
class T(unittest.TestCase):
 def fixture(self,p):
  for n in ['README.md','LICENSE','SECURITY.md','CONTRIBUTING.md','.gitignore']: (p/n).write_text('# x')
  (p/'tests').mkdir();(p/'.github/workflows').mkdir(parents=True);(p/'.github/dependabot.yml').write_text('version: 2')
 def test_score(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);self.fixture(p);(p/'.github/workflows/ci.yml').write_text('permissions:\n  contents: read\nsteps:\n - uses: actions/checkout@'+'a'*40)
   r=repodoctor.analyze(p);self.assertGreaterEqual(r['score'],90);self.assertIn('summary',r)
 def test_unpinned_action(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);self.fixture(p);(p/'.github/workflows/ci.yml').write_text('steps:\n - uses: actions/checkout@v7')
   r=repodoctor.analyze(p);self.assertTrue(any(x['check']=='unpinned-action' for x in r['findings']))
if __name__=='__main__':unittest.main()
