import unittest,pathlib,sys
sys.path.insert(0,str(pathlib.Path(__file__).parents[1]));import regression
class T(unittest.TestCase):
 def reports(self):
  base={"score":90,"findings":[{"level":"warning","check":"docs","message":"Missing X"},{"level":"info","check":"ci","message":"Old"}]};cur={"score":86,"findings":[{"level":"warning","check":"docs","message":"Missing X"},{"level":"critical","check":"secrets","message":"Potential secret"}]};return cur,base
 def test_compare(self):
  cur,base=self.reports();r=regression.compare_reports(cur,base);self.assertEqual(r["summary"],{"new":1,"resolved":1,"persistent":1});self.assertEqual(r["score_delta"],-4)
 def test_fail_threshold(self):
  cur,base=self.reports();self.assertTrue(regression.should_fail(regression.compare_reports(cur,base),"critical"))
 def test_annotations(self):
  cur,base=self.reports();a=regression.annotations(regression.compare_reports(cur,base));self.assertTrue(a[0].startswith("::error"))
 def test_message_change_is_new(self):
  base={"score":90,"findings":[{"level":"warning","check":"links","message":"A"}]};cur={"score":88,"findings":[{"level":"warning","check":"links","message":"B"}]};r=regression.compare_reports(cur,base);self.assertEqual(r["summary"]["new"],1);self.assertEqual(r["summary"]["resolved"],1)
if __name__=="__main__":unittest.main()
