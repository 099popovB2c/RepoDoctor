#!/usr/bin/env python3
import argparse, json, os, re, subprocess, sys
from pathlib import Path

SECRET_PATTERNS={
 'private_key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
 'aws_access_key': re.compile(r'AKIA[0-9A-Z]{16}'),
 'generic_secret': re.compile(r'(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}')
}
SKIP={'.git','node_modules','.venv','venv','dist','build','coverage'}
TEXT_EXT={'.md','.txt','.py','.js','.ts','.tsx','.jsx','.json','.yml','.yaml','.toml','.ini','.env','.sh','.ps1','.html','.css','.java','.go','.rs'}

def files(root):
 for p in root.rglob('*'):
  if any(x in SKIP for x in p.parts): continue
  if p.is_file(): yield p

def read_text(p,max_bytes=2_000_000):
 try:
  if p.stat().st_size>max_bytes:return ''
  return p.read_text(encoding='utf-8',errors='ignore')
 except:return ''

def rel_links(root):
 bad=[]
 for p in files(root):
  if p.suffix.lower()!='.md':continue
  txt=read_text(p)
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',txt):
   t=target.split('#')[0].strip()
   if not t or '://' in t or t.startswith(('mailto:','data:','#')):continue
   if not (p.parent/t).resolve().exists(): bad.append(f'{p.relative_to(root)} -> {t}')
 return bad

def git_status(root):
 try:
  r=subprocess.run(['git','-C',str(root),'status','--porcelain'],capture_output=True,text=True,timeout=3)
  return [x for x in r.stdout.splitlines() if x.strip()]
 except:return []

def analyze(root):
 root=root.resolve(); findings=[]; score=100
 def add(level,check,msg,penalty=0):
  nonlocal score; findings.append({'level':level,'check':check,'message':msg});score=max(0,score-penalty)
 essentials=[('README.md',15),('LICENSE',10),('SECURITY.md',5),('CONTRIBUTING.md',5)]
 for n,pen in essentials:
  if not (root/n).exists():add('warning','docs',f'Missing {n}',pen)
  else:add('ok','docs',f'Found {n}')
 if not (root/'.github/workflows').exists():add('info','ci','No GitHub Actions workflow found',4)
 else:add('ok','ci','GitHub Actions workflow directory found')
 secret_hits=[]; todos=0; large=[]
 for p in files(root):
  try:
   if p.stat().st_size>10*1024*1024: large.append(f'{p.relative_to(root)} ({p.stat().st_size/1024/1024:.1f} MB)')
  except: pass
  if p.suffix.lower() in TEXT_EXT or p.name.startswith('.'):
   txt=read_text(p); todos+=len(re.findall(r'\b(?:TODO|FIXME)\b',txt))
   for name,rx in SECRET_PATTERNS.items():
    if rx.search(txt): secret_hits.append(f'{p.relative_to(root)} [{name}]')
 if secret_hits:add('critical','secrets',f'Potential secrets: {", ".join(secret_hits[:8])}',30)
 else:add('ok','secrets','No common secret patterns detected')
 if large:add('warning','files',f'Large files: {", ".join(large[:8])}',5)
 if todos:add('info','todo',f'{todos} TODO/FIXME markers')
 bad=rel_links(root)
 if bad:add('warning','links',f'Broken relative links: {", ".join(bad[:10])}',min(12,len(bad)*2))
 else:add('ok','links','No broken relative Markdown links found')
 dirty=git_status(root)
 if dirty:add('info','git',f'Working tree has {len(dirty)} uncommitted entries')
 deps={}
 pkg=root/'package.json'
 if pkg.exists():
  try:
   d=json.loads(pkg.read_text()); deps['npm']=len(d.get('dependencies',{}))+len(d.get('devDependencies',{}))
  except:add('warning','dependencies','package.json is invalid JSON',5)
 req=root/'requirements.txt'
 if req.exists(): deps['python']=len([x for x in req.read_text().splitlines() if x.strip() and not x.startswith('#')])
 if deps:add('info','dependencies',f'Dependency declarations: {deps}')
 return {'path':str(root),'score':score,'grade':'A' if score>=90 else 'B' if score>=80 else 'C' if score>=70 else 'D' if score>=60 else 'F','findings':findings}

def md(r):
 lines=[f"# RepoDoctor report\n",f"**Score:** {r['score']}/100 ({r['grade']})\n",f"**Path:** `{r['path']}`\n",'## Findings\n']
 icons={'ok':'✅','info':'ℹ️','warning':'⚠️','critical':'❌'}
 lines += [f"- {icons.get(x['level'],'•')} **{x['check']}** — {x['message']}" for x in r['findings']]
 return '\n'.join(lines)+'\n'

def main():
 ap=argparse.ArgumentParser();ap.add_argument('repo',nargs='?',default='.');ap.add_argument('--json');ap.add_argument('--markdown');a=ap.parse_args();r=analyze(Path(a.repo));print(md(r));
 if a.json: Path(a.json).parent.mkdir(parents=True,exist_ok=True);Path(a.json).write_text(json.dumps(r,indent=2),encoding='utf8')
 if a.markdown: Path(a.markdown).parent.mkdir(parents=True,exist_ok=True);Path(a.markdown).write_text(md(r),encoding='utf8')
if __name__=='__main__':main()
