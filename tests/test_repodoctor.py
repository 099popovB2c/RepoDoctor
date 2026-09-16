import unittest,tempfile,pathlib,sys
sys.path.insert(0,str(pathlib.Path(__file__).parents[1]));import repodoctor
class T(unittest.TestCase):
 def test_score(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);(p/'README.md').write_text('# x');(p/'LICENSE').write_text('MIT')
   r=repodoctor.analyze(p);self.assertGreater(r['score'],0);self.assertIn('grade',r)
if __name__=='__main__':unittest.main()
