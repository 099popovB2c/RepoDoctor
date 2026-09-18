#!/usr/bin/env python3
import argparse,json,re,subprocess,urllib.request
from pathlib import Path
VERSION='0.4.0'
SECRET_PATTERNS={'private_key':re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),'aws_access_key':re.compile(r'AKIA[0-9A-Z]{16}'),'generic_secret':re.compile(r'(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}')}
SKIP={'.git','node_modules','.venv','venv','dist','build','coverage','__pycache__'};TEXT_EXT={'.md','.txt','.py','.js','.ts','.tsx','.jsx','.json','.yml','.yaml','.toml','.ini','.env','.sh','.ps1','.html','.css','.java','.go','.rs'};BINARY_EXT={'.exe','.dll','.so','.dylib','.bin','.jar','.war','.apk','.ipa','.msi','.deb','.rpm','.zip','.7z','.rar'};LOCKFILES=('package-lock.json','npm-shrinkwrap.json','pnpm-lock.yaml','yarn.lock','poetry.lock','Pipfile.lock','uv.lock','Cargo.lock','go.sum')
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
   if t and '://' not in t and not t.startswith(('mailto:','data:','#')) and not (p.parent/t).resolve().exists():bad.append(f'{p.relative_to(root)} -> {t}')
 return bad
def git_status(root):
 try:return [x for x in subprocess.run(['git','-C',str(root),'status','--porcelain'],capture_output=True,text=True,timeout=3).stdout.splitlines() if x.strip()]
 except:return []
def workflow_findings(root):
 out=[];wdir=root/'.github/workflows'
 if not wdir.exists():return out
 texts=[]
 for p in list(wdir.glob('*.yml'))+list(wdir.glob('*.yaml')):
  txt=read_text(p);texts.append(txt);name=str(p.relative_to(root))
  if not re.search(r'(?m)^permissions\s*:',txt):out.append(('warning','workflow-permissions',f'{name}: no top-level permissions block',4))
  if re.search(r'(?m)^\s*pull_request_target\s*:',txt):out.append(('critical','pull-request-target',f'{name}: uses pull_request_target; review checkout/execution carefully',10))
  for m in re.finditer(r'(?m)^\s*-?\s*uses:\s*([^\s#]+)',txt):
   ref=m.group(1)
   if ref.startswith(('./','docker://')) or '@' not in ref:continue
   if not re.fullmatch(r'[0-9a-fA-F]{40}',ref.rsplit('@',1)[1]):out.append(('warning','unpinned-action',f'{name}: {ref} is not pinned to a full commit SHA',2))
 joined='\n'.join(texts).lower()
 if 'github/codeql-action' in joined:out.append(('ok','sast','CodeQL workflow detected',0))
 elif 'semgrep' in joined or 'snyk' in joined:out.append(('ok','sast','SAST workflow detected',0))
 else:out.append(('info','sast','No CodeQL/SAST workflow detected',2))
 return out
def dependency_findings(root):
 out=[];manifests=[root/'package.json',root/'requirements.txt',root/'pyproject.toml',root/'Cargo.toml',root/'go.mod']
 if any(p.exists() for p in manifests):
  locks=[n for n in LOCKFILES if (root/n).exists()];out.append(('ok','lockfile',f"Lockfile(s): {', '.join(locks)}",0) if locks else ('warning','lockfile','Dependency manifest found but no recognized lockfile',4))
 req=root/'requirements.txt'
 if req.exists():
  loose=[s for s in map(str.strip,req.read_text(errors='ignore').splitlines()) if s and not s.startswith(('#','-')) and '==' not in s and ' @ ' not in s]
  if loose:out.append(('warning','dependency-pinning',f'Unpinned Python dependencies: {", ".join(loose[:8])}',3))
 return out
def binary_artifacts(root):
 hits=[]
 for p in files(root):
  if p.suffix.lower() in BINARY_EXT:
   try:hits.append(f'{p.relative_to(root)} ({p.stat().st_size/1024/1024:.1f} MB)')
   except:hits.append(str(p.relative_to(root)))
 return hits
def release_findings(root):
 out=[('ok','release','VERSION file found',0) if (root/'VERSION').exists() else ('info','release','No VERSION file found',1)]
 out.append(('ok','changelog','Changelog found',0) if any((root/x).exists() for x in ('CHANGELOG.md','CHANGES.md','HISTORY.md')) else ('info','changelog','No changelog found',1))
 try:
  tags=subprocess.run(['git','-C',str(root),'tag','--points-at','HEAD'],capture_output=True,text=True,timeout=3).stdout.strip()
  if tags:out.append(('ok','release-tag',f'HEAD tagged: {tags.replace(chr(10),", ")}',0))
 except:pass
 return out
def pinned_packages(root):
 pkgs=[];req=root/'requirements.txt'
 if req.exists():
  for s in map(str.strip,req.read_text(errors='ignore').splitlines()):
   m=re.match(r'^([A-Za-z0-9_.-]+)==([^\s;]+)',s)
   if m:pkgs.append({'package':{'ecosystem':'PyPI','name':m.group(1)},'version':m.group(2)})
 lock=root/'package-lock.json'
 if lock.exists():
  try:
   for path,meta in json.loads(lock.read_text()).get('packages',{}).items():
    if path.startswith('node_modules/') and meta.get('version'):pkgs.append({'package':{'ecosystem':'npm','name':path.split('node_modules/',1)[1]},'version':meta['version']})
  except:pass
 return pkgs[:100]
def osv_scan(root,timeout=12):
 q=pinned_packages(root)
 if not q:return {'status':'no-pinned-packages','vulnerabilities':[]}
 req=urllib.request.Request('https://api.osv.dev/v1/querybatch',data=json.dumps({'queries':q}).encode(),headers={'Content-Type':'application/json','User-Agent':f'RepoDoctor/{VERSION}'})
 try:
  with urllib.request.urlopen(req,timeout=timeout) as r:d=json.loads(r.read().decode())
  v=[]
  for pkg,res in zip(q,d.get('results',[])):
   for x in res.get('vulns',[]):v.append({'package':pkg['package']['name'],'version':pkg['version'],'id':x.get('id'),'summary':x.get('summary','')})
  return {'status':'ok','queries':len(q),'vulnerabilities':v}
 except Exception as e:return {'status':'error','error':str(e),'vulnerabilities':[]}
def analyze(root,run_osv=False):
 root=root.resolve();findings=[];score=100
 def add(level,check,msg,penalty=0):
  nonlocal score;findings.append({'level':level,'check':check,'message':msg});score=max(0,score-penalty)
 for n,pen in [('README.md',15),('LICENSE',10),('SECURITY.md',5),('CONTRIBUTING.md',5)]:add('ok','docs',f'Found {n}') if (root/n).exists() else add('warning','docs',f'Missing {n}',pen)
 add('ok','hygiene','Found .gitignore') if (root/'.gitignore').exists() else add('warning','hygiene','Missing .gitignore',4);add('ok','tests','Test directory found') if any((root/x).exists() for x in ('tests','test','__tests__')) else add('warning','tests','No conventional test directory found',5);add('ok','ci','GitHub Actions workflow directory found') if (root/'.github/workflows').exists() else add('info','ci','No GitHub Actions workflow found',4)
 for x in workflow_findings(root)+dependency_findings(root)+release_findings(root):add(*x)
 add('ok','dependency-updates','Dependency update automation found') if (root/'.github/dependabot.yml').exists() or (root/'.github/dependabot.yaml').exists() or (root/'renovate.json').exists() else add('info','dependency-updates','No Dependabot/Renovate config found',2)
 secret_hits=[];todos=0;large=[]
 for p in files(root):
  try:
   if p.stat().st_size>10*1024*1024:large.append(f'{p.relative_to(root)} ({p.stat().st_size/1024/1024:.1f} MB)')
  except:pass
  if p.suffix.lower() in TEXT_EXT or p.name.startswith('.'):
   txt=read_text(p);todos+=len(re.findall(r'\b(?:TODO|FIXME)\b',txt))
   for name,rx in SECRET_PATTERNS.items():
    if rx.search(txt):secret_hits.append(f'{p.relative_to(root)} [{name}]')
 add('critical','secrets',f'Potential secrets: {", ".join(secret_hits[:8])}',30) if secret_hits else add('ok','secrets','No common secret patterns detected')
 if large:add('warning','files',f'Large files: {", ".join(large[:8])}',5)
 b=binary_artifacts(root);add('warning','binary-artifacts',f'Committed binary/archive artifacts: {", ".join(b[:8])}',min(8,len(b)*2)) if b else add('ok','binary-artifacts','No common binary/archive artifacts committed')
 if todos:add('info','todo',f'{todos} TODO/FIXME markers')
 bad=rel_links(root);add('warning','links',f'Broken relative links: {", ".join(bad[:10])}',min(12,len(bad)*2)) if bad else add('ok','links','No broken relative Markdown links found')
 dirty=git_status(root)
 if dirty:add('info','git',f'Working tree has {len(dirty)} uncommitted entries')
 osv=osv_scan(root) if run_osv else {'status':'not-run','vulnerabilities':[]}
 if osv.get('vulnerabilities'):add('critical','vulnerabilities',f"OSV found {len(osv['vulnerabilities'])} vulnerability matches",min(30,10+len(osv['vulnerabilities'])*2))
 elif run_osv and osv.get('status')=='ok':add('ok','vulnerabilities','OSV found no matches for pinned dependencies')
 counts={lvl:sum(1 for x in findings if x['level']==lvl) for lvl in ('critical','warning','info','ok')}
 return {'version':VERSION,'path':str(root),'score':score,'grade':'A' if score>=90 else 'B' if score>=80 else 'C' if score>=70 else 'D' if score>=60 else 'F','summary':counts,'findings':findings,'osv':osv}
def md(r):
 icons={'ok':'✅','info':'ℹ️','warning':'⚠️','critical':'❌'};return '\n'.join(['# RepoDoctor report','',f"**Score:** {r['score']}/100 ({r['grade']})",f"**Path:** `{r['path']}`",f"**Findings:** {r['summary']['critical']} critical · {r['summary']['warning']} warnings · {r['summary']['info']} info",'','## Findings','']+[f"- {icons.get(x['level'],'•')} **{x['check']}** — {x['message']}" for x in r['findings']])+'\n'
def sarif(r):
 level={'critical':'error','warning':'warning','info':'note'};return {'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json','runs':[{'tool':{'driver':{'name':'RepoDoctor','version':VERSION}},'results':[{'ruleId':x['check'],'level':level[x['level']],'message':{'text':x['message']}} for x in r['findings'] if x['level']!='ok']}]}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('repo',nargs='?',default='.');ap.add_argument('--json');ap.add_argument('--markdown');ap.add_argument('--sarif');ap.add_argument('--osv',action='store_true');ap.add_argument('--fail-below',type=int);a=ap.parse_args();r=analyze(Path(a.repo),a.osv);print(md(r))
 if a.json:Path(a.json).parent.mkdir(parents=True,exist_ok=True);Path(a.json).write_text(json.dumps(r,indent=2),encoding='utf8')
 if a.markdown:Path(a.markdown).parent.mkdir(parents=True,exist_ok=True);Path(a.markdown).write_text(md(r),encoding='utf8')
 if a.sarif:Path(a.sarif).parent.mkdir(parents=True,exist_ok=True);Path(a.sarif).write_text(json.dumps(sarif(r),indent=2),encoding='utf8')
 if a.fail_below is not None and r['score']<a.fail_below:raise SystemExit(2)
if __name__=='__main__':main()
