import os,json,time,hmac,hashlib,secrets,sqlite3,re,base64,threading,urllib.request,urllib.parse
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
import numpy as np
from sklearn.ensemble import IsolationForest
from cryptography.fernet import Fernet
D=os.path.dirname(os.path.abspath(__file__))
if os.path.exists(D+'/.env'):
    for l in open(D+'/.env'):
        if '=' in l and not l.startswith('#'):
            k,v=l.split('=',1);os.environ.setdefault(k.strip(),v.split('#')[0].strip())
E=os.environ.get;DEMO=E('DEMO_MODE','true')=='true'
KF=D+'/ballot.key'
if not os.path.exists(KF):open(KF,'wb').write(Fernet.generate_key())
FER=Fernet(open(KF,'rb').read())
db=sqlite3.connect(D+'/vote2.db',check_same_thread=False);db.row_factory=sqlite3.Row;L=threading.RLock()
db.executescript('''
create table if not exists voters(id integer primary key,name,voter_id unique,mobile unique,email,dob,pw,has_voted int default 0,otp_failures int default 0,login_attempts int default 0);
create table if not exists otps(mobile,hash,exp,attempts int default 0,sent real,used int default 0);
create table if not exists sess(token primary key,uid,role,created real,otp_ok int default 0,otp2_ok int default 0,reqs text default '[]',vote_attempts int default 0,score int,level text,reasons text default '[]');
create table if not exists admin(user primary key,pw,email);
create table if not exists reset(hash,user,exp);
create table if not exists elections(eid primary key,name,descr,type,start real,end real,tz,status,results default 'HIDDEN',verified int default 0,all_voters int default 1,created_by,created real);
create table if not exists cands(id integer primary key autoincrement,eid,code,name,party,position,bio,photo);
create table if not exists elig(eid,uid,primary key(eid,uid));
create table if not exists voted(eid,uid,primary key(eid,uid));
create table if not exists ballots(ballot_id primary key,eid,enc);
create table if not exists blocks(idx integer primary key,prev,hash,ts,eid,ballot_id,enc_ref,tx);
create table if not exists audit(id integer primary key,ts,type,sid,risk,msg,eid,actor);
''')
for t,c in [('voters',"status text default 'UNVERIFIED'"),('voters','face_fail int default 0'),('voters','la_ts real default 0'),('sess','face_ok int default 0'),('sess','live_ok int default 0'),('sess','face_conf real'),('sess','face_fail int default 0'),('sess','live_fail int default 0'),('sess','chal text'),('sess','chal_exp real default 0')]:
    try:db.execute(f'alter table {t} add column {c}')
    except Exception:pass
db.executescript('create table if not exists faces(uid integer primary key,enc,bio_id,created real);create table if not exists rsess(th primary key,uid,otp_ok int default 0,face_ok int default 0,face_fail int default 0,exp real);')
def hpw(p,s=None):
    s=s or secrets.token_bytes(16);return base64.b64encode(s).decode()+'$'+hashlib.pbkdf2_hmac('sha256',p.encode(),s,200000).hex()
def cpw(p,h):
    s,x=h.split('$');return hmac.compare_digest(hpw(p,base64.b64decode(s)),h)
if not db.execute('select 1 from admin').fetchone():
    db.execute('insert into admin values(?,?,?)',('Admin',hpw(E('ADMIN_PASSWORD','Admin@123')),'admin@example.com'))
db.commit()
def audit(t,sid='-',risk='-',msg='',eid='-',actor='-'):
    with L:db.execute('insert into audit(ts,type,sid,risk,msg,eid,actor) values(?,?,?,?,?,?,?)',(time.strftime('%Y-%m-%d %H:%M:%S'),t,(sid or '-')[:8],risk,msg,eid,actor));db.commit()
# ---- AI trust engine: IsolationForest on a synthetic baseline of normal sessions + explainable penalties
rng=np.random.default_rng(7)
base=np.c_[rng.poisson(.2,800),rng.poisson(1.2,800),rng.gamma(2,4,800),rng.uniform(0,900,800),rng.poisson(.05,800)]
IF=IsolationForest(n_estimators=150,contamination=.05,random_state=7).fit(base)
def trust(s,v):
    now=time.time();reqs=[t for t in json.loads(s['reqs']) if now-t<60]
    f=[v['otp_failures'],v['login_attempts'],len(reqs),now-s['created'],s['vote_attempts']];why=[]
    pen=0
    if f[0]:pen+=min(f[0]*9,40);why.append(f'{f[0]} failed OTP attempt(s)')
    if f[1]>3:pen+=min((f[1]-3)*6,20);why.append(f'{f[1]} login attempts')
    if f[2]>25:pen+=min(f[2]-25,25);why.append(f'Unusual request frequency ({f[2]}/min)')
    if f[4]:pen+=15*f[4];why.append(f'{f[4]} repeated voting attempt(s)')
    ff=s['face_fail'] or 0;lf=s['live_fail'] or 0;fc=s['face_conf']
    if ff:pen+=min(ff*12,36);why.append(f'{ff} face verification failure(s)')
    if lf:pen+=min(lf*10,30);why.append(f'{lf} failed liveness challenge(s)')
    if fc is not None and fc<60:pen+=10;why.append(f'Low face match confidence ({fc:.0f}%)')
    an=float(IF.score_samples([f])[0]);ml=int(max(0,min(25,(-an-.55)*120)))
    if ml>5:why.append(f'Isolation Forest flagged session pattern as anomalous (score {an:.2f})')
    sc=int(max(0,100-pen-ml));lv='LOW' if sc>=80 else 'MEDIUM' if sc>=50 else 'HIGH'
    return sc,lv,why,{'otp_failures':f[0],'login_attempts':f[1],'req_per_min':f[2],'repeat_votes':f[4],'ml_anomaly':round(an,3),'face_failures':ff,'liveness_failures':lf,'face_confidence':fc}
def refresh(s,v):
    sc,lv,why,feat=trust(s,v)
    db.execute('update sess set score=?,level=?,reasons=? where token=?',(sc,lv,json.dumps(why),s['token']));db.commit()
    if s['score']!=sc:audit('TRUST_SCORE_UPDATED',s['token'],lv,f'score={sc}')
    if lv=='HIGH' and s['level']!='HIGH':audit('ANOMALY_DETECTED',s['token'],lv,'; '.join(why))
    return {'score':sc,'risk':lv,'security':{'LOW':'STANDARD','MEDIUM':'ELEVATED','HIGH':'HIGH'}[lv],'reasons':why,'features':feat,
      'required':{'LOW':['Password','OTP','Face match','Liveness (2 challenges)'],'MEDIUM':['Password','OTP','Face match','Liveness (3 challenges)','Additional OTP'],'HIGH':['Blocked - security review']}[lv]}
# ---- SMS provider abstraction
def sms_send(mobile,code):
    p=(E('SMS_PROVIDER') or '').lower()
    def call(url,data=None,hdr=None):
        return json.loads(urllib.request.urlopen(urllib.request.Request(url,data,hdr or {}),timeout=10).read() or b'{}')
    if p=='twilio' and E('TWILIO_ACCOUNT_SID') and E('TWILIO_AUTH_TOKEN') and E('TWILIO_PHONE_NUMBER'):
        sid=E('TWILIO_ACCOUNT_SID');r=urllib.request.Request(f'https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json',urllib.parse.urlencode({'To':'+91'+mobile,'From':E('TWILIO_PHONE_NUMBER'),'Body':f'Your voting verification code is {code}. Valid for 3 minutes.'}).encode())
        r.add_header('Authorization','Basic '+base64.b64encode(f"{sid}:{E('TWILIO_AUTH_TOKEN')}".encode()).decode());urllib.request.urlopen(r,timeout=10);return 'sms'
    if p=='fast2sms' and E('FAST2SMS_API_KEY'):
        j=call('https://www.fast2sms.com/dev/bulkV2?'+urllib.parse.urlencode({'authorization':E('FAST2SMS_API_KEY'),'variables_values':code,'route':'otp','numbers':mobile}))
        if not j.get('return'):raise RuntimeError('Fast2SMS rejected request: '+str(j.get('message')))
        return 'sms'
    if p=='2factor' and E('TWOFACTOR_API_KEY'):
        j=call(f"https://2factor.in/API/V1/{E('TWOFACTOR_API_KEY')}/SMS/{mobile}/{code}")
        if j.get('Status')!='Success':raise RuntimeError('2Factor rejected request: '+str(j))
        return 'sms'
    if p=='msg91' and E('MSG91_AUTH_KEY') and E('MSG91_TEMPLATE_ID'):
        j=call('https://control.msg91.com/api/v5/otp?'+urllib.parse.urlencode({'template_id':E('MSG91_TEMPLATE_ID'),'mobile':'91'+mobile,'authkey':E('MSG91_AUTH_KEY'),'otp':code}),b'{}',{'Content-Type':'application/json'})
        if j.get('type')!='success':raise RuntimeError('MSG91 rejected request: '+str(j))
        return 'sms'
    if DEMO and not p:print(f'\n[DEMO ONLY - no SMS sent] OTP for ***{mobile[-4:]}: Your voting verification code is {code}\n',flush=True);return 'demo'
    raise RuntimeError('SMS service is not configured.')
def chain_hash(i,prev,ts,e,b,ref,tx):return hashlib.sha256(f'{i}|{prev}|{ts}|{e}|{b}|{ref}|{tx}'.encode()).hexdigest()
def verify_chain():
    prev='0'*64;res=[]
    for b in db.execute('select * from blocks order by idx'):
        ok_h=chain_hash(b['idx'],b['prev'],b['ts'],b['eid'],b['ballot_id'],b['enc_ref'],b['tx'])==b['hash'];ok_p=b['prev']==prev
        enc=db.execute('select enc from ballots where ballot_id=?',(b['ballot_id'],)).fetchone()
        ok_t=bool(enc) and hashlib.sha256(enc['enc'].encode()).hexdigest()==b['enc_ref']
        res.append({'block':b['idx'],'hash_ok':ok_h,'prev_ok':ok_p,'ballot_ok':ok_t});prev=b['hash']
    return {'valid':all(r['hash_ok'] and r['prev_ok'] and r['ballot_ok'] for r in res),'blocks':len(res),'detail':res}
def blocks_pub():return [dict(idx=b['idx'],eid=b['eid'],prev=b['prev'],hash=b['hash'],ts=b['ts'],ballot_id=b['ballot_id'],enc_ref=b['enc_ref'],tx=b['tx']) for b in db.execute('select * from blocks order by idx')]
class H(BaseHTTPRequestHandler):
    def log_message(s,*a):pass
    def send(s,c,o):
        b=json.dumps(o).encode();s.send_response(c);s.send_header('Content-Type','application/json')
        for k,v in {'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Cache-Control':'no-store','Content-Security-Policy':"default-src 'self' 'unsafe-inline'"}.items():s.send_header(k,v)
        s.send_header('Content-Length',str(len(b)));s.end_headers();s.wfile.write(b)
    def do_GET(s):
        if not s.path.startswith('/api/'):
            b=open(D+'/index.html','rb').read();s.send_response(200);s.send_header('Content-Type','text/html');s.send_header('Content-Length',str(len(b)))
            s.send_header('X-Frame-Options','DENY');s.send_header('Permissions-Policy','camera=(self)');s.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self' https://cdn.jsdelivr.net; frame-ancestors 'none'");s.end_headers();s.wfile.write(b);return
        s.route('GET',{})
    def do_PUT(s):s.do_POST('PUT')
    def do_DELETE(s):s.route('DELETE',{})
    def do_POST(s,mm='POST'):
        try:n=int(s.headers.get('Content-Length',0));assert n<450000;d=json.loads(s.rfile.read(n) or b'{}')
        except Exception:return s.send(400,{'error':'Invalid request body'})
        s.route(mm,d)
    def route(s,m,d):
        try:
            tick()
            with L:s.dispatch(m,d)
        except Exception as e:s.send(500,{'error':'Server error: '+str(e)})
    def auth(s,role):
        t=(s.headers.get('Authorization') or '')[7:];r=db.execute('select * from sess where token=?',(t,)).fetchone()
        if not r or r['role']!=role or time.time()-r['created']>3600:s.send(401,{'error':'Session expired or unauthorized'});return None
        q=json.loads(r['reqs']);q=[x for x in q if time.time()-x<60]+[time.time()]
        db.execute('update sess set reqs=? where token=?',(json.dumps(q),t));db.commit();return db.execute('select * from sess where token=?',(t,)).fetchone()
    def newsess(s,uid,role):
        t=secrets.token_urlsafe(32);db.execute('insert into sess(token,uid,role,created) values(?,?,?,?)',(t,uid,role,time.time()));db.commit();return t
    def dispatch(s,m,d):
        p=s.path.split('?')[0];S=s.send
        if p=='/api/config':return S(200,{'demo_mode':DEMO,'sms_configured':bool(E('SMS_PROVIDER'))})
        if s.authx(m,d,p):return
        if s.elections(m,d,p):return
        if p=='/api/public':
            vc=verify_chain();out=[]
            for e in db.execute("select * from elections where status!='DRAFT' order by start desc"):
                x=einfo(e)
                if e['results']=='PUBLISHED':x['results']=results(e['eid'])['rows']
                out.append(x)
            return S(200,{'registered':db.execute('select count(*) from voters').fetchone()[0],'blocks':vc['blocks'],'chain_valid':vc['valid'],'elections':out})
        if p=='/api/chain':return S(200,{'blocks':blocks_pub()})
        if p=='/api/chain/verify':return S(200,verify_chain())
        if p=='/api/admin/login' and m=='POST':
            a=db.execute('select * from admin where user=?',(d.get('username',''),)).fetchone()
            if not a or not cpw(d.get('password',''),a['pw']):audit('ADMIN_LOGIN_FAILED',msg='bad credentials');return S(401,{'error':'Invalid admin credentials'})
            t=s.newsess(0,'admin');audit('ADMIN_LOGIN',t,msg='admin signed in');return S(200,{'token':t})
        if p=='/api/admin/forgot' and m=='POST':
            a=db.execute('select * from admin where email=?',(d.get('email',''),)).fetchone()
            if a:
                tok=secrets.token_urlsafe(24);db.execute('insert into reset values(?,?,?)',(hashlib.sha256(tok.encode()).hexdigest(),a['user'],time.time()+900));db.commit()
                print(f'\n[DEMO ONLY - email not sent] Admin reset token: {tok}\n',flush=True) if DEMO else None
            return S(200,{'ok':True,'msg':'If the email is registered, a reset link has been issued.'})
        if p=='/api/admin/reset' and m=='POST':
            r=db.execute('select * from reset where hash=? and exp>?',(hashlib.sha256(d.get('token','').encode()).hexdigest(),time.time())).fetchone();pw=d.get('password','')
            if not r:return S(400,{'error':'Invalid or expired token'})
            if len(pw)<8:return S(400,{'error':'Password too short'})
            db.execute('update admin set pw=? where user=?',(hpw(pw),r['user']));db.execute('delete from reset where hash=?',(r['hash'],));db.commit();audit('ADMIN_PASSWORD_RESET',msg='password changed');return S(200,{'ok':True})
        if p.startswith('/api/admin/'):
            if s.admin(m,d,p):return
        S(404,{'error':'Not found'})
    # ---------- authentication: register / login / OTP / face / liveness / password reset ----------
    def authx(s,m,d,p):
        S=s.send
        try:
            if p=='/api/register' and m=='POST':
                e=chk_reg(d)
                if e:S(400,{'error':'; '.join(e)});return True
                try:db.execute('insert into voters(name,voter_id,mobile,email,dob,pw,status) values(?,?,?,?,?,?,?)',(d['name'].strip(),d['voter_id'],d['mobile'],d['email'],d['dob'],hpw(d['password']),'UNVERIFIED'));db.commit()
                except sqlite3.IntegrityError:S(409,{'error':'Voter ID or mobile already registered'});return True
                uid=db.execute('select id from voters where voter_id=?',(d['voter_id'],)).fetchone()[0];t=s.newsess(uid,'voter');audit('USER_REGISTERED',t,msg='account created (UNVERIFIED)');S(200,{'ok':True,'token':t});return True
            if p=='/api/login' and m=='POST':
                ident=(d.get('identifier') or d.get('voter_id') or '').strip().upper();v=db.execute('select * from voters where upper(voter_id)=? or mobile=?',(ident,ident)).fetchone()
                if not v:cpw(d.get('password',''),hpw('x'));S(401,{'error':'Invalid credentials'});return True
                if time.time()-(v['la_ts'] or 0)>900:db.execute('update voters set login_attempts=0,otp_failures=0 where id=?',(v['id'],));db.commit();v=db.execute('select * from voters where id=?',(v['id'],)).fetchone()
                if v['login_attempts']>=10:audit('LOGIN_THROTTLED',msg='too many attempts');S(429,{'error':'Too many login attempts. Try again in 15 minutes.'});return True
                db.execute('update voters set login_attempts=login_attempts+1,la_ts=? where id=?',(time.time(),v['id']));db.commit()
                if not cpw(d.get('password',''),v['pw']):audit('LOGIN_FAILED',msg='wrong password');S(401,{'error':'Invalid credentials'});return True
                if v['status'] in('LOCKED','SUSPENDED'):audit('LOGIN_BLOCKED',msg=v['status']);S(403,{'error':f"Account {v['status'].lower()}. Contact the election administrator."});return True
                t=s.newsess(v['id'],'voter');audit('VOTER_LOGIN',t,msg='password accepted');S(200,{'token':t,'name':v['name'],'status':v['status']});return True
            if p=='/api/pw/forgot' and m=='POST':
                ident=(d.get('identifier') or '').strip();v=db.execute('select * from voters where upper(voter_id)=upper(?) or mobile=? or lower(email)=lower(?)',(ident,ident,ident)).fetchone()
                tok=secrets.token_urlsafe(24);db.execute('insert into rsess(th,uid,exp) values(?,?,?)',(hashlib.sha256(tok.encode()).hexdigest(),v['id'] if v else 0,time.time()+900));db.commit()
                audit('PASSWORD_RESET_REQUESTED',msg='request received')
                S(200,{'token':tok,'masked':('+91 ******'+v['mobile'][-4:]) if v else '+91 ******0000'});return True
            r=re.fullmatch(r'/api/pw/(otp|otp/verify|face|reset)',p)
            if r and m=='POST':
                tok=d.get('token','');rs=db.execute('select * from rsess where th=? and exp>?',(hashlib.sha256(tok.encode()).hexdigest(),time.time())).fetchone()
                if not rs:S(400,{'error':'Reset session expired. Start again.'});return True
                v=db.execute('select * from voters where id=?',(rs['uid'],)).fetchone();k=r.group(1)
                if k=='otp':
                    if v:mode=otp_issue(v['mobile'],tok,'reset');S(200,{'sent':True,'mode':mode,'expires_in':180,'notice':'DEMO ONLY: no real SMS sent; code printed on server console' if mode=='demo' else 'SMS dispatched'})
                    else:S(200,{'sent':True,'expires_in':180})
                    return True
                if not v:S(400,{'error':'Invalid verification code.'});return True
                if k=='otp/verify':
                    er=otp_check(v['mobile'],tok,d.get('code',''),'reset',v['id'])
                    if er:S(er[0],er[1]);return True
                    db.execute('update rsess set otp_ok=1 where th=?',(rs['th'],));db.commit();S(200,{'verified':True});return True
                if not rs['otp_ok']:S(403,{'error':'Verify the OTP first'});return True
                if k=='face':
                    if rs['face_fail']>=3:S(429,{'error':'Too many failed face attempts. Start again later.'});return True
                    best,conf=face_match(v['id'],d.get('descriptor'))
                    if best is None or best>FACE_T:
                        db.execute('update rsess set face_fail=face_fail+1 where th=?',(rs['th'],));db.commit();audit('FACE_VERIFICATION_FAILED','reset',msg='password reset');S(400,{'error':'FACE MISMATCH','attempts_left':max(0,2-rs['face_fail'])});return True
                    db.execute('update rsess set face_ok=1 where th=?',(rs['th'],));db.commit();audit('FACE_VERIFIED','reset',msg='password reset');S(200,{'verified':True,'confidence':conf});return True
                if not rs['face_ok']:S(403,{'error':'Verify your face first'});return True
                er=pw_err(d.get('password',''))
                if er:S(400,{'error':er});return True
                db.execute('update voters set pw=?,login_attempts=0,otp_failures=0 where id=?',(hpw(d['password']),v['id']));db.execute('delete from rsess where uid=?',(v['id'],));db.execute("delete from sess where uid=? and role='voter'",(v['id'],));db.commit()
                audit('PASSWORD_RESET_COMPLETED','reset',msg='password updated');S(200,{'ok':True});return True
            if not(p in('/api/logout','/api/me','/api/otp/send','/api/otp/verify','/api/mobile/change','/api/face/enroll','/api/face/verify','/api/liveness/start','/api/liveness/verify')):return False
            se=s.auth('voter')
            if not se:return True
            v=db.execute('select * from voters where id=?',(se['uid'],)).fetchone();tk=se['token']
            if p=='/api/me':
                t=refresh(se,v);S(200,{'name':v['name'],'status':v['status'],'masked':'+91 ******'+v['mobile'][-4:],'otp_verified':bool(se['otp_ok']),'otp2_verified':bool(se['otp2_ok']),'face_ok':bool(se['face_ok']),'live_ok':bool(se['live_ok']),'trust':t,'next':nextstep(se,v,t)});return True
            if p=='/api/otp/send':
                mode=otp_issue(v['mobile'],tk,tk);S(200,{'sent':True,'mode':mode,'masked':'+91 ******'+v['mobile'][-4:],'expires_in':180,'notice':'DEMO ONLY: no real SMS sent; code printed on server console' if mode=='demo' else 'SMS dispatched'});return True
            if p=='/api/otp/verify':
                er=otp_check(v['mobile'],tk,d.get('code',''),tk,v['id'])
                if er:S(er[0],er[1]);return True
                col='otp_ok' if not se['otp_ok'] else 'otp2_ok';db.execute(f'update sess set {col}=1 where token=?',(tk,))
                if v['status']=='UNVERIFIED':db.execute("update voters set status='OTP_VERIFIED' where id=?",(v['id'],))
                db.commit();audit('OTP_VERIFIED',tk,msg=col);S(200,{'verified':True});return True
            if p=='/api/logout':db.execute('delete from sess where token=?',(tk,));db.commit();audit('VOTER_LOGOUT',tk);S(200,{'ok':True});return True
            if p=='/api/mobile/change':
                if v['status']!='UNVERIFIED':S(403,{'error':'Mobile number can only be changed before verification'});return True
                if not re.fullmatch(r'[6-9][0-9]{9}',d.get('mobile','')):S(400,{'error':'Enter a valid 10-digit Indian mobile number'});return True
                try:db.execute('update voters set mobile=? where id=?',(d['mobile'],v['id']));db.commit()
                except sqlite3.IntegrityError:S(409,{'error':'That mobile number is already registered'});return True
                audit('MOBILE_CHANGED',tk,msg='before verification');S(200,{'masked':'+91 ******'+d['mobile'][-4:]});return True
            if p=='/api/face/enroll':
                if v['status'] not in('OTP_VERIFIED','FACE_ENROLLED') or not se['otp_ok']:S(403,{'error':'Verify your mobile number first'});return True
                sm=d.get('samples') or []
                if len(sm)<5 or len(sm)>12 or not all(okdesc(x.get('descriptor')) for x in sm):S(400,{'error':'Enrollment needs 5 clear face samples'});return True
                need=['straight','straight','left','right','blink']
                if sorted(x.get('step') for x in sm)!=sorted(need):S(400,{'error':'Enrollment steps incomplete'});return True
                ref=next(x for x in sm if x['step']=='straight')['descriptor']
                if any(fdist(ref,x['descriptor'])>0.6 for x in sm):audit('FACE_VERIFICATION_FAILED',tk,msg='enrollment samples inconsistent');S(400,{'error':'Samples are from different faces. Only one person may enroll.'});return True
                if any(not live_metrics(x['step'],x.get('metrics') or {}) for x in sm):audit('LIVENESS_FAILED',tk,msg='enrollment');S(400,{'error':'Liveness could not be confirmed. Repeat the head-turn and blink steps.'});return True
                bio='BIO-'+secrets.token_hex(4).upper();enc=FER.encrypt(json.dumps([x['descriptor'] for x in sm]).encode()).decode()
                db.execute('insert or replace into faces values(?,?,?,?)',(v['id'],enc,bio,time.time()));db.execute("update voters set status='FACE_ENROLLED' where id=?",(v['id'],));audit('FACE_ENROLLED',tk,msg=bio)
                db.execute("update voters set status='ACTIVE' where id=?",(v['id'],));db.commit();audit('FACE_ENROLLMENT_COMPLETED',tk,msg=bio);audit('ACCOUNT_ACTIVATED',tk);S(200,{'bio_id':bio,'status':'ACTIVE'});return True
            if v['status'] in('LOCKED','SUSPENDED'):S(403,{'error':'Account '+v['status'].lower()});return True
            if p=='/api/face/verify':
                if not se['otp_ok']:S(403,{'error':'Verify OTP first'});return True
                if se['face_fail']>=3:S(429,{'error':'Too many failed face attempts for this session.'});return True
                best,conf=face_match(v['id'],d.get('descriptor'))
                if best is None:S(400,{'error':'No enrolled face or invalid capture'});return True
                if best>FACE_T:
                    db.execute('update sess set face_fail=face_fail+1 where token=?',(tk,));db.execute('update voters set face_fail=face_fail+1 where id=?',(v['id'],))
                    if v['face_fail']+1>=6:db.execute("update voters set status='LOCKED' where id=?",(v['id'],));audit('ACCOUNT_LOCKED',tk,msg='repeated face mismatch')
                    db.commit();audit('FACE_VERIFICATION_FAILED',tk,msg='mismatch');S(400,{'error':'FACE MISMATCH','attempts_left':max(0,2-se['face_fail'])});return True
                db.execute('update sess set face_ok=1,face_conf=? where token=?',(conf,tk));db.execute('update voters set face_fail=0 where id=?',(v['id'],));db.commit();audit('FACE_VERIFIED',tk,msg=f'confidence {conf}%');S(200,{'verified':True,'confidence':conf});return True
            if p=='/api/liveness/start':
                if not se['face_ok']:S(403,{'error':'Verify face first'});return True
                t=refresh(se,v)
                if t['risk']=='HIGH':S(403,{'error':'Session restricted','analysis':t});return True
                n=2 if t['risk']=='LOW' else 3;steps=secrets.SystemRandom().sample(['blink','left','right','smile'],n);nonce=secrets.token_hex(8)
                db.execute('update sess set chal=?,chal_exp=? where token=?',(json.dumps({'nonce':nonce,'steps':steps,'t0':time.time()}),time.time()+90,tk));db.commit();S(200,{'nonce':nonce,'steps':steps});return True
            if p=='/api/liveness/verify':
                ch=json.loads(se['chal'] or '{}')
                if not ch or time.time()>se['chal_exp'] or ch.get('nonce')!=d.get('nonce'):S(400,{'error':'Liveness challenge expired. Start again.'});return True
                if se['live_fail']>=3:S(429,{'error':'Too many failed liveness attempts.'});return True
                res=d.get('results') or [];why=''
                if len(res)!=len(ch['steps']):why='step count mismatch'
                elif time.time()-ch['t0']<1.5:why='completed implausibly fast'
                else:
                    for x,st in zip(res,ch['steps']):
                        if x.get('step')!=st or not live_metrics(st,x.get('metrics') or {}):why=f'{st} movement not detected';break
                        if not okdesc(x.get('descriptor')):why='invalid face sample';break
                        if (face_match(v['id'],x['descriptor'])[0] or 9)>FACE_T+0.05:why='face changed during liveness';break
                ok=not why
                db.execute('update sess set chal=NULL where token=?',(tk,))
                if not ok:db.execute('update sess set live_fail=live_fail+1 where token=?',(tk,));db.commit();audit('LIVENESS_FAILED',tk,msg=why);S(400,{'error':'Liveness check failed. Follow each instruction.','attempts_left':max(0,2-se['live_fail'])});return True
                db.execute('update sess set live_ok=1 where token=?',(tk,));db.commit();audit('LIVENESS_VERIFIED',tk,msg=','.join(ch['steps']));S(200,{'verified':True});return True
        except PermissionError as ex:S(429,{'error':str(ex)});return True
        except RuntimeError as ex:S(503,{'error':str(ex)});return True
        return False
    # ---------- voter-facing election APIs ----------
    def elections(s,m,d,p):
        S=s.send
        if p=='/api/elections' and m=='GET':
            se=s.auth('voter')
            if not se:return True
            out=[]
            for e in db.execute("select * from elections where status!='DRAFT' order by start desc"):
                x=einfo(e);x['eligible_me']=is_elig(e,se['uid']);x['voted_me']=bool(db.execute('select 1 from voted where eid=? and uid=?',(e['eid'],se['uid'])).fetchone());out.append(x)
            S(200,{'now':time.time(),'elections':out});return True
        r=re.fullmatch(r'/api/elections/([A-Z0-9-]+)(/vote)?',p)
        if not r:return False
        se=s.auth('voter')
        if not se:return True
        e=db.execute("select * from elections where eid=? and status!='DRAFT'",(r.group(1),)).fetchone()
        if not e:S(404,{'error':'Election not found'});return True
        if not r.group(2):
            x=einfo(e);x['eligible_me']=is_elig(e,se['uid']);x['cands']=[dict(c) for c in db.execute('select id,code,name,party,position,bio,photo from cands where eid=? order by id',(e['eid'],))] if x['eligible_me'] else [];x['now']=time.time();S(200,x);return True
        if m!='POST':return False
        eid=e['eid'];v=db.execute('select * from voters where id=?',(se['uid'],)).fetchone()
        if e['status']=='PAUSED':S(403,{'error':'Voting is temporarily paused by the election administrator'});return True
        if e['status']=='CLOSED':S(403,{'error':'Voting has closed for this election'});return True
        if e['status']!='ACTIVE':S(403,{'error':'Voting has not started'});return True
        if not is_elig(e,se['uid']):audit('INELIGIBLE_VOTE_ATTEMPT',se['token'],eid=eid);S(403,{'error':'You are not eligible for this election'});return True
        if db.execute('select 1 from voted where eid=? and uid=?',(eid,se['uid'])).fetchone():
            db.execute('update sess set vote_attempts=vote_attempts+1 where token=?',(se['token'],));db.commit();audit('REPEAT_VOTE_ATTEMPT',se['token'],eid=eid,msg='already voted');S(409,{'error':'You have already voted in this election.'});return True
        t=refresh(se,v)
        if t['risk']=='HIGH':S(403,{'error':'Voting restricted pending security review','analysis':t});return True
        if v['status']!='ACTIVE':S(403,{'error':'Your account is not active. Complete OTP and face enrollment.'});return True
        if not se['otp_ok'] or not se['face_ok'] or not se['live_ok'] or(t['risk']=='MEDIUM' and not se['otp2_ok']):S(403,{'error':'Additional verification required','analysis':t});return True
        c=db.execute('select * from cands where id=? and eid=?',(d.get('candidate_id'),eid)).fetchone()
        if not c:S(400,{'error':'Invalid candidate'});return True
        try:db.execute('insert into voted values(?,?)',(eid,se['uid']))
        except sqlite3.IntegrityError:S(409,{'error':'You have already voted in this election.'});return True
        bid='BLT-'+secrets.token_hex(4).upper();enc=FER.encrypt(json.dumps({'c':c['id'],'e':eid,'n':secrets.token_hex(8)}).encode()).decode()
        audit('BALLOT_ENCRYPTED',se['token'],t['risk'],bid,eid);ref=hashlib.sha256(enc.encode()).hexdigest();audit('HASH_GENERATED',se['token'],t['risk'],ref[:16],eid)
        last=db.execute('select * from blocks order by idx desc').fetchone();idx=(last['idx']+1) if last else 1;prev=last['hash'] if last else '0'*64
        tx='TX-'+secrets.token_hex(4).upper();ts=time.strftime('%Y-%m-%dT%H:%M:%S');h=chain_hash(idx,prev,ts,eid,bid,ref,tx)
        db.execute('insert into ballots values(?,?,?)',(bid,eid,enc));db.execute('insert into blocks values(?,?,?,?,?,?,?,?)',(idx,prev,h,ts,eid,bid,ref,tx));db.commit()
        audit('VOTE_CAST',se['token'],t['risk'],'ballot recorded',eid);audit('BLOCKCHAIN_TRANSACTION_CREATED',se['token'],t['risk'],tx,eid)
        S(200,{'ballot_id':bid,'tx':tx,'hash':'0x'+h,'block':idx});return True
    # ---------- admin APIs ----------
    def admin(s,m,d,p):
        S=s.send;se=s.auth('admin')
        if not se:return True
        A='Admin';tk=se['token']
        if p=='/api/admin/stats':
            st={r[0]:r[1] for r in db.execute('select status,count(*) from elections group by status')};el=[einfo(e) for e in db.execute("select * from elections where status!='DRAFT'")]
            tv=sum(x['votes'] for x in el);te=sum(x['eligible'] for x in el);lv={r[0]:r[1] for r in db.execute("select level,count(*) from sess where role='voter' and level is not null group by level")}
            S(200,{'status':{k:st.get(k,0) for k in('DRAFT','SCHEDULED','ACTIVE','PAUSED','CLOSED')},'total':sum(st.values()),'voters':db.execute('select count(*) from voters').fetchone()[0],'votes':tv,'turnout':round(100*tv/te,1) if te else 0,
              'sessions':db.execute("select count(*) from sess where role='voter' and ?-created<1800",(time.time(),)).fetchone()[0],'alerts':db.execute("select count(*) from audit where type='ANOMALY_DETECTED'").fetchone()[0],'tx':db.execute('select count(*) from blocks').fetchone()[0],'risk':{k:lv.get(k,0) for k in('LOW','MEDIUM','HIGH')}});return True
        if p=='/api/admin/voters':S(200,[dict(r) for r in db.execute("select id,name,voter_id,'******'||substr(mobile,7) mobile,status from voters")]);return True
        r=re.fullmatch(r'/api/admin/voters/(\d+)/status',p)
        if r and m=='POST':
            ns=d.get('status')
            if ns not in('ACTIVE','LOCKED','SUSPENDED'):S(400,{'error':'Invalid status'});return True
            if ns=='ACTIVE' and not db.execute('select 1 from faces where uid=?',(r.group(1),)).fetchone():S(400,{'error':'Voter has no enrolled face; cannot activate'});return True
            db.execute('update voters set status=?,face_fail=0,login_attempts=0 where id=?',(ns,r.group(1)));db.commit();audit('VOTER_STATUS_CHANGED',tk,msg=f'{r.group(1)} -> {ns}',actor='Admin');S(200,{'ok':True});return True
        if p=='/api/admin/audit':
            q=urllib.parse.parse_qs(s.path.partition('?')[2]).get('eid',[None])[0]
            rows=db.execute('select ts,type,sid,risk,msg,eid,actor from audit '+('where eid=? ' if q else '')+'order by id desc limit 200',(q,) if q else ()).fetchall();S(200,[dict(r) for r in rows]);return True
        if p=='/api/admin/elections' and m=='GET':S(200,[einfo(e) for e in db.execute('select * from elections order by created desc')]);return True
        try:
            if p=='/api/admin/elections' and m=='POST':
                f=chk_election(d);eid='ELX-%s-%s'%(time.strftime('%Y'),secrets.token_hex(3).upper())
                db.execute("insert into elections values(?,?,?,?,?,?,?,'DRAFT','HIDDEN',0,?,?,?)",(eid,f['name'],f['descr'],f['type'],f['start'],f['end'],f['tz'],0 if d.get('mode')=='selected' else 1,A,time.time()))
                set_elig(eid,d);[add_cand(eid,c) for c in d.get('cands',[])]
                db.commit();audit('ELECTION_CREATED',tk,msg=f['name'],eid=eid,actor=A);S(200,{'eid':eid});return True
            r=re.fullmatch(r'/api/admin/elections/([A-Z0-9-]+)(?:/([a-z-]+))?',p)
            if r:
                e=db.execute('select * from elections where eid=?',(r.group(1),)).fetchone();sub=r.group(2);eid=r.group(1)
                if not e:S(404,{'error':'Election not found'});return True
                if not sub and m=='GET':
                    x=einfo(e);x['cands']=[dict(c) for c in db.execute('select * from cands where eid=? order by id',(eid,))];x['mode']='all' if e['all_voters'] else 'selected';x['ids']=[r[0] for r in db.execute('select voter_id from elig join voters on voters.id=elig.uid where eid=?',(eid,))];S(200,x);return True
                if not sub and m=='PUT':
                    need(e,'DRAFT','Only DRAFT elections can be edited');f=chk_election(d)
                    db.execute('update elections set name=?,descr=?,type=?,start=?,end=?,tz=?,all_voters=? where eid=?',(f['name'],f['descr'],f['type'],f['start'],f['end'],f['tz'],0 if d.get('mode')=='selected' else 1,eid));set_elig(eid,d);db.commit()
                    audit('ELECTION_UPDATED',tk,msg=f['name'],eid=eid,actor=A);audit('ELIGIBLE_VOTERS_UPDATED',tk,eid=eid,actor=A);S(200,{'ok':True});return True
                if not sub and m=='DELETE':
                    need(e,'DRAFT','Only DRAFT elections can be deleted')
                    if urllib.parse.parse_qs(s.path.partition('?')[2]).get('confirm',[''])[0]!='DELETE':raise ValueError('Type DELETE to confirm')
                    for t in('cands','elig','voted'):db.execute(f'delete from {t} where eid=?',(eid,))
                    db.execute('delete from elections where eid=?',(eid,));db.commit();audit('ELECTION_DELETED',tk,msg=e['name'],eid=eid,actor=A);S(200,{'ok':True});return True
                if sub=='candidates' and m=='POST':
                    need(e,'DRAFT','Candidates can only be changed while the election is DRAFT');add_cand(eid,d);db.commit();audit('CANDIDATE_ADDED',tk,msg=d.get('name','')[:40],eid=eid,actor=A);S(200,{'ok':True});return True
                if sub=='action' and m=='POST':
                    a=d.get('action');n=time.time();st=e['status']
                    if a=='publish':
                        need(e,'DRAFT','Only DRAFT elections can be published')
                        if db.execute('select count(*) from cands where eid=?',(eid,)).fetchone()[0]<2:raise ValueError('At least two candidates are required')
                        if e['end']<=n:raise ValueError('End time is in the past - edit the schedule first')
                        if not e['all_voters'] and not db.execute('select 1 from elig where eid=?',(eid,)).fetchone():raise ValueError('No eligible voters selected')
                        new,ev='SCHEDULED','ELECTION_SCHEDULED'
                    elif a=='start':need(e,'SCHEDULED','Only SCHEDULED elections can be started');new,ev='ACTIVE','ELECTION_STARTED'
                    elif a=='pause':need(e,'ACTIVE','Only ACTIVE elections can be paused');new,ev='PAUSED','ELECTION_PAUSED'
                    elif a=='resume':need(e,'PAUSED','Only PAUSED elections can be resumed');new,ev='ACTIVE','ELECTION_RESUMED'
                    elif a=='close':
                        if st not in('SCHEDULED','ACTIVE','PAUSED'):raise ValueError('Election cannot be closed from state '+st)
                        if d.get('confirm')!=e['name']:raise ValueError('Type the exact election name to confirm closing')
                        new,ev='CLOSED','ELECTION_CLOSED'
                    else:raise ValueError('Unknown action')
                    db.execute('update elections set status=? where eid=?',(new,eid));db.commit();audit(ev,tk,msg=f'{st} -> {new}',eid=eid,actor=A);S(200,{'status':new});return True
                if sub=='monitor':
                    x=einfo(e);x['vpm']=db.execute('select count(*) from blocks where eid=? and ts>=?',(eid,time.strftime('%Y-%m-%dT%H:%M:%S',time.localtime(time.time()-60)))).fetchone()[0]
                    x['sessions']=db.execute("select count(*) from sess where role='voter' and ?-created<1800",(time.time(),)).fetchone()[0];x['alerts']=db.execute("select count(*) from audit where eid=? and type in('ANOMALY_DETECTED','REPEAT_VOTE_ATTEMPT','INELIGIBLE_VOTE_ATTEMPT')",(eid,)).fetchone()[0];S(200,x);return True
                if sub in('results','verify-results','publish-results'):
                    if e['status']!='CLOSED':raise ValueError('Results are available only after the election is CLOSED')
                    res=results(eid)
                    if sub=='results':res['verified']=bool(e['verified']);res['published']=e['results']=='PUBLISHED';res['election']=einfo(e);S(200,res);return True
                    if sub=='verify-results':
                        if not res['integrity']['ok']:audit('RESULTS_VERIFICATION_FAILED',tk,eid=eid,actor=A);raise ValueError('Integrity check FAILED - results cannot be verified')
                        db.execute('update elections set verified=1 where eid=?',(eid,));db.commit();audit('RESULTS_VERIFIED',tk,eid=eid,actor=A);S(200,res);return True
                    if not e['verified']:raise ValueError('Verify results before publishing')
                    db.execute("update elections set results='PUBLISHED' where eid=?",(eid,));db.commit();audit('RESULTS_PUBLISHED',tk,eid=eid,actor=A);S(200,{'ok':True});return True
            r=re.fullmatch(r'/api/admin/candidates/(\d+)',p)
            if r:
                c=db.execute('select * from cands where id=?',(r.group(1),)).fetchone();e=db.execute('select * from elections where eid=?',(c['eid'],)).fetchone() if c else None
                if not c:S(404,{'error':'Candidate not found'});return True
                need(e,'DRAFT','Candidates can only be changed while the election is DRAFT')
                if m=='DELETE':db.execute('delete from cands where id=?',(c['id'],));ev='CANDIDATE_REMOVED'
                else:
                    n=(d.get('name') or '').strip()
                    if len(n)<2:raise ValueError('Candidate name required')
                    ph=okphoto(d['photo']) if d.get('photo') else c['photo']
                    db.execute('update cands set name=?,party=?,position=?,bio=?,photo=? where id=?',(n[:80],d.get('party','')[:80],d.get('position','')[:80],d.get('bio','')[:300],ph,c['id']));ev='CANDIDATE_UPDATED'
                db.commit();audit(ev,tk,msg=c['name'][:40],eid=c['eid'],actor=A);S(200,{'ok':True});return True
        except ValueError as ex:db.rollback();S(400,{'error':str(ex)});return True
        return False

# ---------- auth helpers ----------
FACE_T=0.5
def pw_err(pw):
    if not(len(pw)>=8 and re.search('[A-Z]',pw) and re.search('[a-z]',pw) and re.search('[0-9]',pw) and re.search('[^A-Za-z0-9]',pw)):return 'Password needs 8+ characters with uppercase, lowercase, a number and a special character'
def chk_reg(d):
    e=[]
    if len(d.get('name','').strip())<3:e.append('Full name required')
    if not re.fullmatch(r'[A-Z]{3}[0-9]{7}',d.get('voter_id','')):e.append('Voter ID must be 3 capital letters + 7 digits (e.g. ABC1234567)')
    if not re.fullmatch(r'[6-9][0-9]{9}',d.get('mobile','')):e.append('Enter a valid 10-digit Indian mobile number')
    if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+',d.get('email','')):e.append('Invalid email')
    try:
        if (time.time()-time.mktime(time.strptime(d.get('dob',''),'%Y-%m-%d')))/31557600<18:e.append('Voter must be at least 18')
    except Exception:e.append('Invalid date of birth')
    if pw_err(d.get('password','')):e.append(pw_err(d['password']))
    return e
def okdesc(x):
    try:return isinstance(x,list) and len(x)==128 and all(isinstance(i,(int,float)) and abs(i)<4 for i in x) and float(np.std(x))>0.01
    except Exception:return False
def fdist(a,b):return float(np.linalg.norm(np.array(a)-np.array(b)))
def face_match(uid,desc):
    r=db.execute('select enc from faces where uid=?',(uid,)).fetchone()
    if not r or not okdesc(desc):return None,0
    best=min(fdist(desc,t) for t in json.loads(FER.decrypt(r['enc'].encode())));return best,round(max(0,min(100,100*(1-best))),1)
def live_metrics(step,mt):
    try:
        if step=='straight':return True
        if step=='blink':return mt['earMin']<=0.21 and mt['earMax']>=0.24
        if step=='left':return mt['yawMax']>=0.10
        if step=='right':return mt['yawMin']<=-0.10
        if step=='smile':return mt['smileMax']>=0.6
    except Exception:pass
    return False
def nextstep(se,v,t):
    if v['status'] in('LOCKED','SUSPENDED') or t['risk']=='HIGH':return 'blocked'
    if not se['otp_ok']:return 'otp'
    if v['status'] in('OTP_VERIFIED','FACE_ENROLLED'):return 'enroll'
    if not se['face_ok']:return 'face'
    if not se['live_ok']:return 'liveness'
    if t['risk']=='MEDIUM' and not se['otp2_ok']:return 'otp2'
    return 'dash'
def otp_issue(mobile,bind,sid):
    o=db.execute('select * from otps where mobile=? order by sent desc',(mobile,)).fetchone()
    if o and time.time()-o['sent']<30:raise PermissionError(f"Please wait {int(30-(time.time()-o['sent']))}s before requesting another code")
    if db.execute('select count(*) from otps where mobile=? and sent>?',(mobile,time.time()-3600)).fetchone()[0]>=6:raise PermissionError('Too many OTP requests. Try again later.')
    code=f'{secrets.randbelow(10**6):06d}'
    try:mode=sms_send(mobile,code)
    except Exception as ex:print('[SMS ERROR]',type(ex).__name__,ex,flush=True);audit('OTP_SEND_FAILED',sid,msg='provider error');raise RuntimeError('SMS service is currently unavailable.')
    db.execute('insert into otps values(?,?,?,0,?,0)',(mobile,hashlib.sha256((code+bind).encode()).hexdigest(),time.time()+180,time.time()));db.commit();audit('OTP_SENT',sid,msg='via '+mode);return mode
def otp_check(mobile,bind,code,sid,uid):
    o=db.execute('select rowid r,* from otps where mobile=? and used=0 order by sent desc',(mobile,)).fetchone()
    if not o or time.time()>o['exp']:return 400,{'error':'This OTP has expired. Request a new code.'}
    if o['attempts']>=3:return 429,{'error':'Too many attempts. Request a new code.'}
    if not hmac.compare_digest(hashlib.sha256((str(code)+bind).encode()).hexdigest(),o['hash']):
        db.execute('update otps set attempts=attempts+1 where rowid=?',(o['r'],));db.execute('update voters set otp_failures=otp_failures+1 where id=?',(uid,));db.commit();audit('OTP_FAILED',sid,msg='wrong code')
        return 400,{'error':'Invalid verification code.','attempts_left':2-o['attempts']}
    db.execute('update otps set used=1 where rowid=?',(o['r'],));db.commit();return None
# ---------- election engine (module level) ----------
def need(e,st,msg):
    if e['status']!=st:raise ValueError(f"{msg} (current state: {e['status']})")
def okphoto(p):
    mt=re.fullmatch(r'data:image/(png|jpeg|webp);base64,([A-Za-z0-9+/=]+)',p or '')
    if not mt or len(p)>300000:raise ValueError('Photo must be PNG, JPEG or WebP under 200 KB')
    if not base64.b64decode(mt.group(2)).startswith({'png':b'\x89PNG','jpeg':b'\xff\xd8\xff','webp':b'RIFF'}[mt.group(1)]):raise ValueError('File content is not a valid image')
    return p
def chk_election(d):
    n=(d.get('name') or '').strip()
    if len(n)<3:raise ValueError('Election name is required (min 3 characters)')
    if d.get('type') not in('General Election','Student Election','Organization Election','Local Election','Custom Election'):raise ValueError('Select an election type')
    try:st,en=float(d['start']),float(d['end'])
    except Exception:raise ValueError('Valid start and end date/time required')
    if en<=st:raise ValueError('End date/time must be after the start date/time')
    return {'name':n[:120],'descr':(d.get('descr') or '')[:500],'type':d['type'],'start':st,'end':en,'tz':str(d.get('tz') or 'UTC')[:40]}
def add_cand(eid,c):
    n=(c.get('name') or '').strip()
    if len(n)<2:raise ValueError('Candidate name required')
    ph=okphoto(c['photo']) if c.get('photo') else ''
    k=db.execute('select count(*) from cands where eid=?',(eid,)).fetchone()[0]+1
    while db.execute('select 1 from cands where eid=? and code=?',(eid,'CND-%03d'%k)).fetchone():k+=1
    db.execute('insert into cands(eid,code,name,party,position,bio,photo) values(?,?,?,?,?,?,?)',(eid,'CND-%03d'%k,n[:80],(c.get('party') or '')[:80],(c.get('position') or '')[:80],(c.get('bio') or '')[:300],ph))
def set_elig(eid,d):
    db.execute('delete from elig where eid=?',(eid,))
    if d.get('mode')=='selected':
        ids=[x.strip().upper() for x in d.get('ids',[]) if x.strip()]
        for x in ids:
            r=db.execute('select id from voters where voter_id=?',(x,)).fetchone()
            if r:db.execute('insert or ignore into elig values(?,?)',(eid,r['id']))
def is_elig(e,uid):return bool(e['all_voters']) or bool(db.execute('select 1 from elig where eid=? and uid=?',(e['eid'],uid)).fetchone())
def einfo(e):
    eid=e['eid'];el=db.execute('select count(*) from voters').fetchone()[0] if e['all_voters'] else db.execute('select count(*) from elig where eid=?',(eid,)).fetchone()[0]
    vt=db.execute('select count(*) from voted where eid=?',(eid,)).fetchone()[0]
    return {'eid':eid,'name':e['name'],'descr':e['descr'],'type':e['type'],'status':e['status'],'start':e['start'],'end':e['end'],'tz':e['tz'],'cands_n':db.execute('select count(*) from cands where eid=?',(eid,)).fetchone()[0],
      'eligible':el,'votes':vt,'turnout':round(100*vt/el,1) if el else 0,'results_status':e['results'],'verified':bool(e['verified'])}
def tick():  # backend-enforced automatic transitions
    n=time.time()
    with L:
        for e in db.execute("select eid,status,start,end from elections where status in('SCHEDULED','ACTIVE','PAUSED')").fetchall():
            if e['end']<=n:db.execute("update elections set status='CLOSED' where eid=?",(e['eid'],));db.commit();audit('ELECTION_CLOSED',msg=f"automatic at end time ({e['status']} -> CLOSED)",eid=e['eid'],actor='system')
            elif e['status']=='SCHEDULED' and e['start']<=n:db.execute("update elections set status='ACTIVE' where eid=?",(e['eid'],));db.commit();audit('ELECTION_STARTED',msg='automatic at start time',eid=e['eid'],actor='system')
def results(eid):
    cs={c['id']:{'candidate':c['name'],'code':c['code'],'votes':0} for c in db.execute('select * from cands where eid=?',(eid,))};ok=inv=0
    for b in db.execute('select enc from ballots where eid=?',(eid,)):
        try:
            x=json.loads(FER.decrypt(b['enc'].encode()))
            if x['e']==eid and x['c'] in cs:cs[x['c']]['votes']+=1;ok+=1
            else:inv+=1
        except Exception:inv+=1
    nb=db.execute('select count(*) from blocks where eid=?',(eid,)).fetchone()[0];nv=db.execute('select count(*) from voted where eid=?',(eid,)).fetchone()[0];ch=verify_chain()
    rows=sorted(cs.values(),key=lambda r:-r['votes'])
    for i,r in enumerate(rows):r['rank']=i+1;r['pct']=round(100*r['votes']/ok,1) if ok else 0
    integ={'chain_valid':ch['valid'],'records_match':nb==nv==ok+inv,'duplicates':max(0,nb-nv),'invalid':inv}
    integ['ok']=integ['chain_valid'] and integ['records_match'] and not inv and not integ['duplicates']
    return {'rows':rows,'total':ok,'integrity':integ}

if __name__=='__main__':
    port=int(E('PORT','8000'));print(f'VoteSecure on http://localhost:{port}  DEMO_MODE={DEMO}');ThreadingHTTPServer(('0.0.0.0',port),H).serve_forever()
