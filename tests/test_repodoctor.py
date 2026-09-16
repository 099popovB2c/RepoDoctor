import unittest,tempfile,pathlib,sys
sys.path.insert(0,str(pathlib.Path(__file__).parents[1]));import repodoctor
class T(unittest.TestCase):
 def fixture(self,p):
  for n in ['README.md','LICENSE','SECURITY.md','CONTRIBUTING.md','.gitignore','VERSION']:(p/n).write_text('# x')
  (p/'tests').mkdir();(p/'.github/workflows').mkdir(parents=True);(p/'.github/dependabot.yml').write_text('version: 2')
 def test_score(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);self.fixture(p);(p/'.github/workflows/ci.yml').write_text('permissions:\n  contents: read\nsteps:\n - uses: actions/checkout@'+'a'*40+'\n - uses: github/codeql-action/analyze@'+'b'*40);r=repodoctor.analyze(p);self.assertGreaterEqual(r['score'],90)
 def test_unpinned_action(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);self.fixture(p);(p/'.github/workflows/ci.yml').write_text('steps:\n - uses: actions/checkout@v7');self.assertTrue(any(x['check']=='unpinned-action' for x in repodoctor.analyze(p)['findings']))
 def test_binary(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);self.fixture(p);(p/'release.zip').write_bytes(b'x');self.assertTrue(repodoctor.binary_artifacts(p))
 def test_sarif(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);self.fixture(p);self.assertEqual(repodoctor.sarif(repodoctor.analyze(p))['version'],'2.1.0')
 def test_pinned(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);(p/'requirements.txt').write_text('requests==2.32.0\n');self.assertEqual(repodoctor.pinned_packages(p)[0]['package']['ecosystem'],'PyPI')
if __name__=='__main__':unittest.main()
