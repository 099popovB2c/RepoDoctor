#!/usr/bin/env python3
import argparse,json,sys
from pathlib import Path
import repodoctor

VERSION="0.4.0"
SEVERITY={"ok":0,"info":1,"warning":2,"critical":3}

def finding_key(x):return (str(x.get("check","")),str(x.get("message","")).strip())
def compare_reports(current,baseline):
    cur={finding_key(x):x for x in current.get("findings",[]) if x.get("level")!="ok"};old={finding_key(x):x for x in baseline.get("findings",[]) if x.get("level")!="ok"};new=[cur[k] for k in cur.keys()-old.keys()];resolved=[old[k] for k in old.keys()-cur.keys()];persistent=[cur[k] for k in cur.keys()&old.keys()];new.sort(key=lambda x:(-SEVERITY.get(x.get("level"),0),x.get("check",""),x.get("message","")));resolved.sort(key=lambda x:(x.get("check",""),x.get("message","")));return {"version":VERSION,"score":current.get("score"),"baseline_score":baseline.get("score"),"score_delta":(current.get("score",0)-baseline.get("score",0)),"new":new,"resolved":resolved,"persistent":persistent,"summary":{"new":len(new),"resolved":len(resolved),"persistent":len(persistent)}}
def should_fail(regression,level="warning"):return any(SEVERITY.get(x.get("level"),0)>=SEVERITY[level] for x in regression.get("new",[]))
def markdown(r):
    lines=["# RepoDoctor regression report","",f"**Score:** {r.get('score')} (baseline {r.get('baseline_score')}, delta {r.get('score_delta'):+})",f"**New:** {r['summary']['new']} · **Resolved:** {r['summary']['resolved']} · **Persistent:** {r['summary']['persistent']}","","## New findings",""];lines += [f"- **{x['level'].upper()} · {x['check']}** — {x['message']}" for x in r["new"]] or ["- None"];lines += ["","## Resolved findings",""];lines += [f"- **{x['check']}** — {x['message']}" for x in r["resolved"]] or ["- None"];return "\n".join(lines)+"\n"
def annotations(r):
    out=[]
    for x in r.get("new",[]):
        cmd="error" if x.get("level")=="critical" else "warning" if x.get("level")=="warning" else "notice";msg=str(x.get("message","")).replace("\r"," ").replace("\n"," ");out.append(f"::{cmd} title=RepoDoctor {x.get('check','finding')}::{msg}")
    return out
def main():
    ap=argparse.ArgumentParser(description="RepoDoctor v0.4 regression gate");ap.add_argument("repo",nargs="?",default=".");ap.add_argument("--baseline",required=True,help="previous RepoDoctor JSON report");ap.add_argument("--json",help="write current RepoDoctor report");ap.add_argument("--regression-json",help="write regression result");ap.add_argument("--markdown",help="write regression Markdown");ap.add_argument("--github-annotations",action="store_true");ap.add_argument("--fail-on-new",choices=("info","warning","critical"));ap.add_argument("--osv",action="store_true");a=ap.parse_args();baseline=json.loads(Path(a.baseline).read_text(encoding="utf8"));current=repodoctor.analyze(Path(a.repo),a.osv);regression=compare_reports(current,baseline);print(markdown(regression))
    if a.json:Path(a.json).parent.mkdir(parents=True,exist_ok=True);Path(a.json).write_text(json.dumps(current,indent=2),encoding="utf8")
    if a.regression_json:Path(a.regression_json).parent.mkdir(parents=True,exist_ok=True);Path(a.regression_json).write_text(json.dumps(regression,indent=2),encoding="utf8")
    if a.markdown:Path(a.markdown).parent.mkdir(parents=True,exist_ok=True);Path(a.markdown).write_text(markdown(regression),encoding="utf8")
    if a.github_annotations:
        for line in annotations(regression):print(line)
    if a.fail_on_new and should_fail(regression,a.fail_on_new):raise SystemExit(3)
if __name__=="__main__":main()
