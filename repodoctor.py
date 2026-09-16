#!/usr/bin/env python3
import argparse,json,re,subprocess,sys
from pathlib import Path
SECRET_PATTERNS={'private_key':re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),'aws_access_key':re.compile(r'AKIA[0-9A-Z]{16}'),'generic_secret':re.compile(r'(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}')}
SKIP={'.git','node_modules','.venv','venv','dist','build','coverage','__pycache__'};TEXT_EXT={'.md','.txt','.py','.js','.ts','.tsx','.jsx','.json','.yml','.yaml','.toml','.ini','.env','.sh','.ps1','.html','.css','.java','.go','.rs'}
def files(root):
 for p in root.rglob('*'):
  if any(x in SKIP for x in p.parts):continue
  if p.is_file():yield p
def read_text(p,max_bytes=2_000_000):
 try:
  if p.stat().st_size>max_bytes:return ''
  return p.read_text(encoding='utf-8',errors='ignore')
 except:return ''
def rel_links(root):
 bad=[]
 for p in files(root):
  if p.suffix.lower()!='.md':continue
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read_text(p)):
   t=target.split('#')[0].strip()
   if not t or '://' in t or t.startswith(('mailto:','data:','#')):continue
   if not (p.parent/t).resolve().exists():bad.append(f'{p.relative_to(root)} -> {t}')
 return bad
def git_status(root):
 try:return [x for x in subprocess.run(['git','-C',str(root),'status','--porcelain'],capture_output=True,text=True,timeout=3).stdout.splitlines() if x.strip()]
 except:return []
def workflow_findings(root):
 out=[];wdir=root/'.github/workflows'
 if not wdir.exists():return out
 for p in list(wdir.glob('*.yml'))+list(wdir.glob('*.yaml')):
  txt=read_text(p);name=str(p.relative_to(root))
  if not re.search(r'(?m)^permissions\s*:',txt):out.append(('warning','workflow-permissions',f'{name}: no top-level permissions block',4))
  if re.search(r'(?m)^\s*pull_request_target\s*:',txt):out.append(('critical','pull-request-target',f'{name}: uses pull_request_target; review checkout/execution carefully',10))
  for m in re.finditer(r'(?m)^\s*-?\s*uses:\s*([^\s#]+)',txt):
   ref=m.group(1)
   if ref.startswith(('./','docker://')) or '@' not in ref:continue
   ver=ref.rsplit('@',1)[1]
   if not re.fullmatch(r'[0-9a-fA-F]{40}',ver):out.append(('warning','unpinned-action',f'{name}: {ref} is not pinned to a full commit SHA',2))
 return out
def analyze(root):
 root=root.resolve();findings=[];score=100
 def add(level,check,msg,penalty=0):
  nonlocal score;findings.append({'level':level,'check':check,'message':msg});score=max(0,score-penalty)
 for n,pen in [('README.md',15),('LICENSE',10),('SECURITY.md',5),('CONTRIBUTING.md',5)]: add('ok','docs',f'Found {n}') if (root/n).exists() else add('warning','docs',f'Missing {n}',pen)
 if (root/'.gitignore').exists():add('ok','hygiene','Found .gitignore')
 else:add('warning','hygiene','Missing .gitignore',4)
 if any((root/x).exists() for x in ('tests','test','__tests__')):add('ok','tests','Test directory found')
 else:add('warning','tests','No conventional test directory found',5)
 if not (root/'.github/workflows').exists():add('info','ci','No GitHub Actions workflow found',4)
 else:add('ok','ci','GitHub Actions workflow directory found')
 for level,check,msg,pen in workflow_findings(root):add(level,check,msg,pen)
 if (root/'.github/dependabot.yml').exists() or (root/'.github/dependabot.yaml').exists() or (root/'renovate.json').exists():add('ok','dependency-updates','Dependency update automation found')
 else:add('info','dependency-updates','No Dependabot/Renovate config found',2)
 if (root/'.github/CODEOWNERS').exists() or (root/'CODEOWNERS').exists():add('ok','codeowners','CODEOWNERS found')
 secret_hits=[];todos=0;large=[]
 for p in files(root):
  try:
   if p.stat().st_size>10*1024*1024:large.append(f'{p.relative_to(root)} ({p.stat().st_size/1024/1024:.1f} MB)')
  except:pass
  if p.suffix.lower() in TEXT_EXT or p.name.startswith('.'):
   txt=read_text(p);todos+=len(re.findall(r'\b(?:TODO|FIXME)\b',txt))
   for name,rx in SECRET_PATTERNS.items():
    if rx.search(txt):secret_hits.append(f'{p.relative_to(root)} [{name}]')
 if secret_hits:add('critical','secrets',f'Potential secrets: {", ".join(secret_hits[:8])}',30)
 else:add('ok','secrets','No common secret patterns detected')
 if large:add('warning','files',f'Large files: {", ".join(large[:8])}',5)
 if todos:add('info','todo',f'{todos} TODO/FIXME markers')
 bad=rel_links(root);add('warning','links',f'Broken relative links: {", ".join(bad[:10])}',min(12,len(bad)*2)) if bad else add('ok','links','No broken relative Markdown links found')
 dirty=git_status(root)
 if dirty:add('info','git',f'Working tree has {len(dirty)} uncommitted entries')
 deps={};pkg=root/'package.json'
 if pkg.exists():
  try:d=json.loads(pkg.read_text());deps['npm']=len(d.get('dependencies',{}))+len(d.get('devDependencies',{}))
  except:add('warning','dependencies','package.json is invalid JSON',5)
 req=root/'requirements.txt'
 if req.exists():deps['python']=len([x for x in req.read_text().splitlines() if x.strip() and not x.startswith('#')])
 if deps:add('info','dependencies',f'Dependency declarations: {deps}')
 counts=dict((lvl,sum(1 for x in findings if x['level']==lvl)) for lvl in ('critical','warning','info','ok'))
 return {'path':str(root),'score':score,'grade':'A' if score>=90 else 'B' if score>=80 else 'C' if score>=70 else 'D' if score>=60 else 'F','summary':counts,'findings':findings}
def md(r):
 icons={'ok':'✅','info':'ℹ️','warning':'⚠️','critical':'❌'};lines=['# RepoDoctor report','',f"**Score:** {r['score']}/100 ({r['grade']})",f"**Path:** `{r['path']}`",f"**Findings:** {r['summary']['critical']} critical · {r['summary']['warning']} warnings · {r['summary']['info']} info",'','## Findings','']+ [f"- {icons.get(x['level'],'•')} **{x['check']}** — {x['message']}" for x in r['findings']]
 return '\n'.join(lines)+'\n'
def main():
 ap=argparse.ArgumentParser();ap.add_argument('repo',nargs='?',default='.');ap.add_argument('--json');ap.add_argument('--markdown');ap.add_argument('--fail-below',type=int);a=ap.parse_args();r=analyze(Path(a.repo));print(md(r))
 if a.json:Path(a.json).parent.mkdir(parents=True,exist_ok=True);Path(a.json).write_text(json.dumps(r,indent=2),encoding='utf8')
 if a.markdown:Path(a.markdown).parent.mkdir(parents=True,exist_ok=True);Path(a.markdown).write_text(md(r),encoding='utf8')
 if a.fail_below is not None and r['score']<a.fail_below:raise SystemExit(2)
if __name__=='__main__':main()
