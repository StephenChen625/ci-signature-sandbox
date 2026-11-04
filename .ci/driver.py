"""Public synthetic-only GitHub experiment. Import is inert; no live local mode.
No artifacts/caches/registry/cloud/deploy access. No long-lived secrets or keys.
"""
import base64,hashlib,json,os,re,stat,subprocess,tempfile,time,urllib.request
from pathlib import Path
LINUX_BYTES=145688404
LINUX_SHA='424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa'
LINUX_URL='https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64'
PATHS={'.ci/binding.json','.ci/driver.py','.ci/trusted-root.json','.github/workflows/signer.yml','.github/workflows/caller.yml','fixtures/probe.txt'}
CHANGED={'.github/workflows/caller.yml','fixtures/probe.txt'}
class Stop(ValueError):pass
def need(v,code):
    if not v:raise Stop(code)
def sha(b):return hashlib.sha256(b).hexdigest()
def wire(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def valid_binding(b,now):
    need(isinstance(b,dict) and set(b)=={'schema','approved_public_test','repository','repository_id','expires'} and b['schema']==1 and b['approved_public_test'] is True,'BINDING_APPROVAL')
    need(isinstance(b['repository'],str) and re.fullmatch('[A-Za-z0-9-]+/ci-signature-sandbox(?:-[A-Za-z0-9-]+)?',b['repository']),'PUBLIC_SANDBOX_NAME')
    need(isinstance(b['repository_id'],str) and re.fullmatch('[1-9][0-9]{0,19}',b['repository_id']),'BINDING_ID')
    need(type(b['expires']) is int and now<b['expires']<=now+86400,'BINDING_EXPIRY')

def prepare(env,event,binding,repository,now):
    valid_binding(binding,now)
    need(env.get('GITHUB_ACTIONS')=='true' and env.get('GITHUB_EVENT_NAME')=='push' and env.get('GITHUB_REF')=='refs/heads/main' and env.get('GITHUB_RUN_ATTEMPT')=='1','EVENT_SCOPE')
    need(env.get('GITHUB_REPOSITORY')==binding['repository'] and env.get('GITHUB_REPOSITORY_ID')==binding['repository_id'],'REPOSITORY_SCOPE')
    need(event.get('repository',{}).get('private') is False and str(event['repository']['id'])==binding['repository_id'] and event['repository']['full_name']==binding['repository'] and event.get('ref')=='refs/heads/main' and event.get('deleted') is False,'PUBLIC_EVENT_REQUIRED')
    commit=env.get('GITHUB_SHA');base=env.get('BASE_COMMIT');run=env.get('GITHUB_RUN_ID')
    need(all(isinstance(v,str) and re.fullmatch('[0-9a-f]{40}',v) for v in (commit,base)) and commit!=base and event.get('after')==commit and isinstance(run,str) and run.isdigit(),'SOURCE_CONTEXT')
    clean={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_NO_REPLACE_OBJECTS':'1','GIT_TERMINAL_PROMPT':'0','GIT_ALLOW_PROTOCOL':''}
    def git(*args,limit=262144):
        v=subprocess.run(['/usr/bin/git','--no-pager','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-C',str(repository),*args],capture_output=True,timeout=10,env=clean)
        need(v.returncode==0 and len(v.stdout)<=limit and len(v.stderr)<16384,'GIT_READ');return v.stdout
    need(git('rev-parse','HEAD').decode().strip()==commit,'CHECKOUT_HEAD')
    need(git('rev-list','--parents','-n','1',commit).decode().split()==[commit,base],'EXACT_PARENT')
    def tree(c):
        leaves={};trees={git('rev-parse',c+'^{tree}').decode().strip()}
        for row in git('ls-tree','-r','-t','-z',c).split(b'\0'):
            if not row:continue
            head,path=row.split(b'\t',1);mode,kind,oid=head.decode().split();path=path.decode()
            need(kind=='tree' and mode=='040000' or kind=='blob' and mode=='100644','TREE_MODE')
            if kind=='tree':trees.add(oid)
            else:need(path not in leaves,'TREE_DUPLICATE');leaves[path]=oid
        return leaves,trees
    old,_=tree(base);target,trees=tree(commit)
    need(set(target)==PATHS and set(old)==PATHS-CHANGED,'SYNTHETIC_FILES_ONLY')
    need({n for n in target if old.get(n)!=target[n]}==CHANGED,'EXACT_TEST_DELTA')
    files={}
    for n in sorted(CHANGED):
        raw=git('cat-file','blob',commit+':'+n,limit=16384);files[n]={'data':base64.b64encode(raw).decode(),'sha256':sha(raw),'size':len(raw)}
    need(base64.b64decode(files['fixtures/probe.txt']['data'])==b'synthetic signature test only\n','FIXTURE_CONTENT')
    objects=[]
    for oid,kind in [(commit,'commit'),*[(t,'tree') for t in sorted(trees)]]:
        raw=git('cat-file',kind,oid,limit=65536);objects.append({'oid':oid,'type':kind,'data':base64.b64encode(raw).decode()})
    package=wire({'schema':1,'repository':binding['repository'],'repository_id':binding['repository_id'],'commit':commit,'base_commit':base,'sequence':1,'job':sha((binding['repository_id']+'/'+run+'/1/'+commit).encode())[:32],'files':files,'objects':objects})
    need(len(package)<=65536,'SMALL_PACKET_ONLY');return package

def download_tool(path):
    # Hash-pinned official public download; no auth headers or user credentials.
    start=time.monotonic();total=0;digest=hashlib.sha256()
    with urllib.request.urlopen(LINUX_URL,timeout=20) as response,path.open('xb') as f:
        need(response.url.startswith('https://'),'TLS_REDIRECT')
        while True:
            need(time.monotonic()-start<120,'DOWNLOAD_DEADLINE');b=response.read(1048576)
            if not b:break
            total+=len(b);need(total<=LINUX_BYTES,'DOWNLOAD_SIZE');digest.update(b);f.write(b)
    need(total==LINUX_BYTES and digest.hexdigest()==LINUX_SHA,'OFFICIAL_TOOL_SHA');path.chmod(0o700)

def command(args,environment):
    v=subprocess.run(args,capture_output=True,timeout=180,env=environment)
    need(v.returncode==0 and len(v.stdout)+len(v.stderr)<=65536,'SIGN_OR_VERIFY_UNCONFIRMED')

def main():
    env=dict(os.environ);need(env.get('GITHUB_ACTIONS')=='true','NO_LOCAL_LIVE_MODE')
    root=Path(env['GITHUB_WORKSPACE']);binding=json.loads((root/'.ci/binding.json').read_bytes());event_path=Path(env['GITHUB_EVENT_PATH']);need(event_path.stat().st_size<=1048576,'EVENT_SIZE');event=json.loads(event_path.read_bytes())
    package=prepare(env,event,binding,root,int(time.time()))
    need(env.get('ACTIONS_ID_TOKEN_REQUEST_URL') and env.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN'),'OIDC_AMBIENT_MISSING')
    # Never read or accept a PAT/cloud/upload key; only GitHub ambient OIDC.
    with tempfile.TemporaryDirectory(prefix='public-signature-',dir=env['RUNNER_TEMP']) as d:
        r=Path(d);r.chmod(0o700);payload=r/'payload.json';payload.write_bytes(package);payload.chmod(0o600);exe=r/'cosign';bundle=r/'bundle.json';download_tool(exe)
        need(int(time.time())<binding['expires'],'EXPIRED_BEFORE_OIDC')
        marker=r/'sign.intent';fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
        clean={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HOME':d,'GITHUB_ACTIONS':'true','ACTIONS_ID_TOKEN_REQUEST_URL':env['ACTIONS_ID_TOKEN_REQUEST_URL'],'ACTIONS_ID_TOKEN_REQUEST_TOKEN':env['ACTIONS_ID_TOKEN_REQUEST_TOKEN']}
        command([str(exe),'sign-blob','--yes','--oidc-provider','github-actions','--bundle',str(bundle),str(payload)],clean)
        need(bundle.is_file() and not bundle.is_symlink() and bundle.stat().st_size<=65536 and payload.read_bytes()==package,'SIGN_OUTPUT')
        public_bundle=bundle.read_bytes();identity='https://github.com/'+binding['repository']+'/.github/workflows/signer.yml@'+env['BASE_COMMIT']
        verify_env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HOME':d}
        command([str(exe),'verify-blob','--bundle',str(bundle),'--trusted-root',str(root/'.ci/trusted-root.json'),'--certificate-identity',identity,'--certificate-oidc-issuer','https://token.actions.githubusercontent.com',str(payload)],verify_env)
        # Only already-public/synthetic material, never JWT/privatekey/raw errors.
        report={'schema':1,'package_b64':base64.b64encode(package).decode(),'bundle_b64':base64.b64encode(public_bundle).decode(),'package_sha256':sha(package),'bundle_sha256':sha(public_bundle),'standard_crypto_verified':True,'full_local_source_admission':'pending'}
        text='PUBLIC_SYNTHETIC_REPORT '+wire(report).decode();need(len(text)<=196608,'PUBLIC_LOG_LIMIT');print(text)
        summary=env.get('GITHUB_STEP_SUMMARY')
        if summary:
            with open(summary,'a') as f:f.write('Public synthetic signing completed. Full local admission remains pending.\n')
if __name__=='__main__':
    try:main()
    except Exception:print('PUBLIC_SYNTHETIC_STOP_NO_AUTOMATIC_RETRY');raise SystemExit(1)
