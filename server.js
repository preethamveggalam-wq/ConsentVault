import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import {fileURLToPath} from 'url';

dotenv.config();
const __filename=fileURLToPath(import.meta.url); const __dirname=path.dirname(__filename);
const PORT=Number(process.env.PORT||8787); const storeFile=path.join(__dirname,'data','store.json');
const app=express(); app.use(cors()); app.use(express.json({limit:'5mb'}));
const now=()=>new Date().toISOString(); const hash=p=>crypto.createHash('sha256').update(String(p)).digest('hex');
const clone=x=>JSON.parse(JSON.stringify(x));
const seed={users:[],encounters:[],requests:[],payments:[],audit:[],chats:[],sessions:[],checkups:[]};
function read(){try{return JSON.parse(fs.readFileSync(storeFile,'utf8'))}catch{return clone(seed)}}
function write(){fs.mkdirSync(path.dirname(storeFile),{recursive:true});fs.writeFileSync(storeFile,JSON.stringify(db,null,2))}
let db=read(); for(const k of Object.keys(seed)) if(!Array.isArray(db[k])) db[k]=[]; for(const s of db.sessions){if(s?.token&&s?.userId) sessions.set(s.token,s)}
const sessions=new Map(); const token=()=>crypto.randomBytes(32).toString('hex'); const id=p=>`${p}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
function auth(req,res,next){const t=(req.headers.authorization||'').replace(/^Bearer\s+/,'');const s=sessions.get(t);if(!s)return res.status(401).json({error:'Session expired. Please sign in again.'});req.user=s;next()}
function user(uid){return db.users.find(u=>u.id===uid)}
function normalizePhone(phone){let n=String(phone||'').replace(/\D/g,'');if(n.startsWith('00'))n=n.slice(2);if(n.startsWith('91')&&n.length===12)n=n.slice(2);if(n.length>10)n=n.slice(-10);return n}
function requesterByPhone(phone){const n=normalizePhone(phone);return db.users.find(u=>u.role==='requester'&&normalizePhone(u.phone)===n)}
function audit(type,details){db.audit.push({id:id('AUD'),type,details,at:now()});}
function expire(){let changed=false;for(const r of db.requests){if(r.status==='ACTIVE'&&r.expiresAt&&new Date(r.expiresAt)<=new Date()){r.status='EXPIRED';audit('CONSENT_EXPIRED',{requestId:r.id,patientId:r.patientId,requesterId:r.requesterId}) ;changed=true}}if(changed)write()}

app.get('/api/health',(_,res)=>res.json({ok:true,gateway:'Requester QR',configured:true,amount:1,currency:'INR'}));
app.post('/api/auth/signup',(req,res)=>{try{const {role,name,email,password,phone='',org=''}=req.body||{};if(!['patient','requester'].includes(role))return res.status(400).json({error:'Choose Patient or Requester.'});if(!name?.trim()||!email?.trim()||!password||password.length<6)return res.status(400).json({error:'Enter your name, email and a password of at least 6 characters.'});if(db.users.some(u=>u.email.toLowerCase()===email.trim().toLowerCase()))return res.status(409).json({error:'An account with this email already exists.'});if(role==='requester'&&phone&&!/^\+?[0-9\s-]{8,18}$/.test(phone))return res.status(400).json({error:'Enter a valid requester phone number.'});const uid=id(role==='patient'?'PT':'REQ');const u={id:uid,role,name:name.trim(),email:email.trim().toLowerCase(),phone:String(phone||'').trim(),org:String(org||'').trim(),passwordHash:hash(password),onboarded:false,wearable:{connected:false,provider:null}};db.users.push(u);write();res.json({ok:true,firstLogin:true,userId:uid})}catch(e){res.status(500).json({error:'Unable to create account.'})}});
app.post('/api/auth/login',(req,res)=>{const {role,login,password}=req.body||{};const v=String(login||'').trim().toLowerCase();const u=db.users.find(x=>x.role===role&&(x.id.toLowerCase()===v||x.email.toLowerCase()===v||String(x.phone||'').toLowerCase()===v));if(!u||u.passwordHash!==hash(password||''))return res.status(401).json({error:'Invalid login details.'});const t=token();const s={token:t,role:u.role,userId:u.id,name:u.name,email:u.email,phone:u.phone||'',org:u.org||'',onboarded:Boolean(u.onboarded),createdAt:now()};sessions.set(t,s);db.sessions=db.sessions.filter(x=>x.userId!==u.id);db.sessions.push(s);write();res.json({ok:true,session:s})});
app.post('/api/auth/logout',auth,(req,res)=>{sessions.delete(req.user.token);db.sessions=db.sessions.filter(x=>x.token!==req.user.token);write();res.json({ok:true})});
app.post('/api/profile/onboarding',auth,(req,res)=>{const u=user(req.user.userId);if(!u)return res.status(404).json({error:'User not found'});const p=req.body?.profile||{};u.name=String(req.body?.name||u.name).trim();u.phone=String(req.body?.phone||u.phone||'').trim();if(u.phone)u.phone=String(req.body?.phone||u.phone||'').trim();if(req.body?.org!==undefined)u.org=String(req.body.org).trim();if(u.role==='requester' && !String(p.paymentQr||u.paymentQr||'').startsWith('data:image/')) return res.status(400).json({error:'Upload your UPI / bank QR image to continue.'});u.profile={...(u.profile||{}),...p};if(u.role==='requester')u.paymentQr=String(p.paymentQr||u.paymentQr||'');u.onboarded=true;const s=sessions.get(req.user.token);if(s){s.name=u.name;s.phone=u.phone;s.org=u.org;s.onboarded=true}write();res.json({ok:true,session:s,profile:u.profile})});

// Patient starts the digital encounter by entering the hospital-provided/requester phone number.
app.post('/api/encounters/start',auth,(req,res)=>{if(req.user.role!=='patient')return res.status(403).json({error:'Only patients can start an encounter.'});const requester=requesterByPhone(req.body?.requesterPhone);if(!requester)return res.status(404).json({error:'No ConsentVault requester is registered with that phone number.'});for(const e of db.encounters){if(e.patientId===req.user.userId&&e.status==='OPEN')e.status='CLOSED'}const patient=user(req.user.userId);const healthIssues=patient?.profile?.conditions||[];const encounter={id:id('ENC'),code:`CV-${new Date().getFullYear()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,patientId:req.user.userId,requesterId:requester.id,requesterName:requester.name,requesterOrg:requester.org,requesterPhone:requester.phone,healthIssues,recommendedTests:recommendedTests(healthIssues),status:'OPEN',createdAt:now(),expiresAt:new Date(Date.now()+24*60*60*1000).toISOString()};db.encounters.push(encounter);audit('ENCOUNTER_CREATED',{encounterId:encounter.id,code:encounter.code,patientId:req.user.userId,requesterId:requester.id});write();res.json({ok:true,encounter,requester:{id:requester.id,name:requester.name,org:requester.org}})});
app.get('/api/patient/state',auth,(req,res)=>{if(req.user.role!=='patient')return res.status(403).json({error:'Patient access required'});expire();const u=user(req.user.userId);const encounters=db.encounters.filter(e=>e.patientId===u.id).sort((a,b)=>b.createdAt.localeCompare(a.createdAt));const requests=db.requests.filter(r=>r.patientId===u.id).sort((a,b)=>b.createdAt.localeCompare(a.createdAt)).map(r=>({...r,paymentQr:r.paymentQr||user(r.requesterId)?.paymentQr||''}));res.json({encounters,requests,active:requests.filter(r=>r.status==='ACTIVE'),profile:u.profile||{},wearable:u.wearable||{}})});
app.post('/api/monitoring/checkup',auth,(req,res)=>{if(req.user.role!=='patient')return res.status(403).json({error:'Patient access required'});const r=db.requests.find(x=>x.id===req.body?.requestId&&x.patientId===req.user.userId&&x.stage==='MONITORING'&&x.status==='ACTIVE');if(!r)return res.status(404).json({error:'Active monitoring consent not found'});const day=Math.max(1,Math.min(Number(req.body?.day)||1,Number(r.durationDays)||1));const allowed=(r.categories||[]);const values=Object.fromEntries(Object.entries(req.body?.values||{}).filter(([k])=>allowed.includes(k)).map(([k,v])=>[k,String(v).slice(0,120)]));const existing=db.checkups.find(x=>x.requestId===r.id&&x.day===day);const item={id:existing?.id||id('CHK'),requestId:r.id,patientId:r.patientId,requesterId:r.requesterId,day,values,notes:String(req.body?.notes||'').slice(0,300),submittedAt:now()};if(existing)Object.assign(existing,item);else db.checkups.push(item);audit('CHECKUP_SUBMITTED',{requestId:r.id,patientId:r.patientId,requesterId:r.requesterId,day});write();res.json({ok:true,checkup:item})});
app.get('/api/monitoring/checkups/:requestId',auth,(req,res)=>{const r=db.requests.find(x=>x.id===req.params.requestId);if(!r)return res.status(404).json({error:'Monitoring request not found'});if(req.user.userId!==r.patientId&&req.user.userId!==r.requesterId)return res.status(403).json({error:'Not authorized'});res.json({ok:true,checkups:db.checkups.filter(x=>x.requestId===r.id).sort((a,b)=>a.day-b.day)})});
app.post('/api/wearable/connect',auth,(req,res)=>{if(req.user.role!=='patient')return res.status(403).json({error:'Patient access required'});const provider=String(req.body?.provider||'Health wearable');const u=user(req.user.userId);u.wearable={connected:true,provider,connectedAt:now(),mode:'demo-ready'};audit('WEARABLE_CONNECTED',{patientId:u.id,provider});write();res.json({ok:true,wearable:u.wearable})});
app.post('/api/wearable/disconnect',auth,(req,res)=>{if(req.user.role!=='patient')return res.status(403).json({error:'Patient access required'});const u=user(req.user.userId);u.wearable={connected:false,provider:null};audit('WEARABLE_DISCONNECTED',{patientId:u.id});write();res.json({ok:true,wearable:u.wearable})});
app.get('/api/wearable/live',auth,(req,res)=>{if(req.user.role!=='patient')return res.status(403).json({error:'Patient access required'});const u=user(req.user.userId);if(!u.wearable?.connected)return res.status(409).json({error:'Wearable is not connected.'});const t=Date.now();res.json({ok:true,mode:'demo-simulator',updatedAt:now(),metrics:{heartRate:72+Math.floor(Math.sin(t/7000)*7+Math.random()*5),spo2:97+Math.floor(Math.random()*2),hrv:48+Math.floor(Math.random()*14),bloodPressure:{systolic:116+Math.floor(Math.random()*7),diastolic:74+Math.floor(Math.random()*6)},temperature:(36.5+Math.random()*.4).toFixed(1),steps:Math.floor((t/90000)%10000),sleep:'7h 18m'}})});
function recommendedTests(issues=[]){const s=new Set();for(const issue of issues){const x=String(issue).toLowerCase();if(x.includes('hypertension')||x.includes('low blood pressure'))['Vitals','ECG / EKG','Wearable Heart Rate','Wearable Blood Pressure'].forEach(v=>s.add(v));if(x.includes('heart disease')||x.includes('heart failure')||x.includes('arrhythmia')||x.includes('stroke'))['ECG / EKG','Echocardiogram','Holter','Stress Test','Cardiology Reports','Vitals','Wearable Heart Rate'].forEach(v=>s.add(v));if(x.includes('diabetes')||x.includes('prediabetes'))['Blood Tests','Hematology','Biochemistry','Vitals','Wearable Heart Rate'].forEach(v=>s.add(v));if(x.includes('kidney'))['Blood Tests','Urine Tests','Biochemistry','Vitals'].forEach(v=>s.add(v));if(x.includes('liver'))['Blood Tests','Biochemistry','Ultrasound'].forEach(v=>s.add(v));if(x.includes('thyroid'))['Blood Tests','Biochemistry'].forEach(v=>s.add(v));if(x.includes('asthma')||x.includes('copd'))['Vitals','Wearable SpO₂','X-Ray'].forEach(v=>s.add(v));if(x.includes('sleep apnea'))['Wearable SpO₂','Wearable Heart Rate','Wearable Sleep','Vitals'].forEach(v=>s.add(v));if(x.includes('anemia')||x.includes('bleeding'))['Blood Tests','Hematology'].forEach(v=>s.add(v));if(x.includes('arthritis')||x.includes('osteoporosis')||x.includes('joint')||x.includes('back / spine'))['X-Ray','MRI','Vitals'].forEach(v=>s.add(v));if(x.includes('cancer'))['Blood Tests','Pathology','CT Scan'].forEach(v=>s.add(v));}return [...s].filter(Boolean)}

app.get('/api/requester/state',auth,(req,res)=>{if(req.user.role!=='requester')return res.status(403).json({error:'Requester access required'});expire();const rawEncounters=db.encounters.filter(e=>e.requesterId===req.user.userId&&e.status==='OPEN').sort((a,b)=>b.createdAt.localeCompare(a.createdAt));const encounters=rawEncounters.map(e=>{const profileRequest=db.requests.find(r=>r.encounterId===e.id&&r.stage==='PROFILE'&&r.status==='PROFILE_APPROVED');const patient=user(e.patientId);const healthIssues=Array.isArray(e.healthIssues)?e.healthIssues:(patient?.profile?.conditions||[]);const autoTests=Array.isArray(e.recommendedTests)&&e.recommendedTests.length?e.recommendedTests:recommendedTests(healthIssues);return {id:e.id,code:e.code,status:e.status,createdAt:e.createdAt,expiresAt:e.expiresAt,requesterName:e.requesterName,requesterOrg:e.requesterOrg,patientId:e.patientId,healthIssues,recommendedTests:autoTests,profileApproved:Boolean(profileRequest)};});const requests=db.requests.filter(r=>r.requesterId===req.user.userId).sort((a,b)=>b.createdAt.localeCompare(a.createdAt)).map(r=>{const {patientId,...safe}=r;return safe});const profileApprovals=requests.filter(r=>r.stage==='PROFILE'&&r.status==='PROFILE_APPROVED').map(r=>{const patient=user(r.patientId);const approved={};if((r.categories||[]).some(c=>['Medical History','Diagnoses','Family History','Surgical History','Hospitalization History'].includes(c)))approved.conditions=patient?.profile?.conditions||[];if((r.categories||[]).includes('Allergies'))approved.allergies=patient?.profile?.allergies||[];if((r.categories||[]).includes('Medications'))approved.medications=patient?.profile?.medications||[];return {requestId:r.id,encounterId:r.encounterId,patientId:r.patientId,categories:r.categories,purpose:r.purpose,approvedHealthProfile:approved,recommendedTests:recommendedTests(approved.conditions||[])}});res.json({encounters,requests,approved:requests.filter(r=>r.stage==='MONITORING'&&r.status==='ACTIVE'),profileApprovals})});
app.post('/api/requests/create',auth,(req,res)=>{if(req.user.role!=='requester')return res.status(403).json({error:'Requester access required'});const {encounterId,categories=[],conditions=[],purpose='',durationDays=7,stage='PROFILE'}=req.body||{};if(!['PROFILE','MONITORING'].includes(stage))return res.status(400).json({error:'Invalid consent stage.'});const e=db.encounters.find(x=>x.id===encounterId&&x.requesterId===req.user.userId&&x.status==='OPEN');if(!e)return res.status(404).json({error:'Encounter not found or closed.'});if(!categories.length)return res.status(400).json({error:'Select at least one health-data category.'});if(!String(purpose).trim())return res.status(400).json({error:'Enter the purpose of access.'});const profileApproved=db.requests.some(r=>r.encounterId===e.id&&r.stage==='PROFILE'&&r.status==='PROFILE_APPROVED');if(stage==='MONITORING'&&!profileApproved)return res.status(409).json({error:'Health Profile Access must be approved before creating a monitoring request.'});const activeStatuses=['PENDING_PATIENT_REVIEW','PROFILE_APPROVED','PAYMENT_PENDING_PATIENT','PAYMENT_PENDING_REQUESTER','ACTIVE'];if(db.requests.some(r=>r.encounterId===e.id&&r.stage===stage&&activeStatuses.includes(r.status)))return res.status(409).json({error:`An active ${stage.toLowerCase()} request already exists for this encounter.`});const requesterQr=String(user(req.user.userId)?.paymentQr||'');const r={id:id('CNS'),stage,encounterId:e.id,patientId:e.patientId,requesterId:req.user.userId,requesterName:req.user.name,requesterOrg:req.user.org,categories,conditions,purpose:String(purpose).trim(),durationDays:Number(durationDays)||7,status:'PENDING_PATIENT_REVIEW',createdAt:now(),approvedAt:null,paidAt:null,startsAt:null,expiresAt:null,paymentId:null,paymentQr:requesterQr};db.requests.push(r);audit('REQUEST_CREATED',{requestId:r.id,encounterId:e.id,requesterId:req.user.userId,stage});write();res.json({ok:true,request:r})});
app.post('/api/requests/:id/decision',auth,(req,res)=>{if(req.user.role!=='patient')return res.status(403).json({error:'Patient access required'});const r=db.requests.find(x=>x.id===req.params.id&&x.patientId===req.user.userId);if(!r)return res.status(404).json({error:'Request not found'});if(r.status!=='PENDING_PATIENT_REVIEW')return res.status(400).json({error:'This request is no longer awaiting your decision.'});const decision=req.body?.decision;if(decision==='deny'){r.status='DENIED';r.decidedAt=now();audit('REQUEST_DENIED',{requestId:r.id,patientId:r.patientId,requesterId:r.requesterId});write();return res.json({ok:true,request:r})}if(decision!=='approve')return res.status(400).json({error:'Invalid decision'});r.approvedAt=now();if(r.stage==='PROFILE'){r.status='PROFILE_APPROVED';audit('PROFILE_ACCESS_APPROVED',{requestId:r.id,patientId:r.patientId,requesterId:r.requesterId});}else{r.status='PAYMENT_PENDING_PATIENT';audit('MONITORING_REQUEST_APPROVED',{requestId:r.id,patientId:r.patientId,requesterId:r.requesterId});}write();res.json({ok:true,request:r})});

app.get('/api/payment/config',(_,res)=>res.json({ok:true,mode:'REQUESTER_QR',amount:1,currency:'INR'}));
app.get('/api/payment/qr/:requestId',auth,(req,res)=>{
  if(req.user.role!=='patient')return res.status(403).json({error:'Patient only'});
  const r=db.requests.find(x=>x.id===req.params.requestId&&x.patientId===req.user.userId);
  if(!r)return res.status(404).json({error:'Request not found'});
  if(r.stage!=='MONITORING'||!['PAYMENT_PENDING_PATIENT','PAYMENT_PENDING_REQUESTER','ACTIVE'].includes(r.status))return res.status(400).json({error:'Payment QR is not available for this request.'});
  const requester=user(r.requesterId);
  const paymentQr=String(requester?.paymentQr||r.paymentQr||'');
  if(paymentQr && r.paymentQr!==paymentQr){r.paymentQr=paymentQr;write();}
  res.json({ok:true,paymentQr});
});


app.post('/api/payment/patient-confirm',auth,(req,res)=>{if(req.user.role!=='patient')return res.status(403).json({error:'Patient only'});const r=db.requests.find(x=>x.id===req.body?.requestId&&x.patientId===req.user.userId);if(!r)return res.status(404).json({error:'Request not found'});if(r.stage!=='MONITORING'||r.status!=='PAYMENT_PENDING_PATIENT')return res.status(400).json({error:'This request is not waiting for patient payment.'});if(!user(r.requesterId)?.paymentQr)return res.status(400).json({error:'Requester has not uploaded a payment QR.'});r.paymentStatus='PATIENT_MARKED_PAID';r.paymentMarkedAt=now();r.status='PAYMENT_PENDING_REQUESTER';audit('PAYMENT_MARKED_PAID',{requestId:r.id,patientId:r.patientId,requesterId:r.requesterId});write();res.json({ok:true,request:r})});
app.post('/api/payment/requester-confirm',auth,(req,res)=>{if(req.user.role!=='requester')return res.status(403).json({error:'Requester only'});const r=db.requests.find(x=>x.id===req.body?.requestId&&x.requesterId===req.user.userId);if(!r)return res.status(404).json({error:'Request not found'});if(r.stage!=='MONITORING'||r.status!=='PAYMENT_PENDING_REQUESTER')return res.status(400).json({error:'No patient payment is awaiting confirmation.'});r.status='ACTIVE';r.paymentStatus='CONFIRMED';r.paidAt=now();r.startsAt=now();r.expiresAt=new Date(Date.now()+r.durationDays*86400000).toISOString();audit('CONSENT_ACTIVATED',{requestId:r.id,patientId:r.patientId,requesterId:r.requesterId,paymentMethod:'REQUESTER_QR'});write();res.json({ok:true,request:r})});

app.post('/api/requests/:id/revoke',auth,(req,res)=>{if(req.user.role!=='patient')return res.status(403).json({error:'Patient access required'});const r=db.requests.find(x=>x.id===req.params.id&&x.patientId===req.user.userId);if(!r||r.status!=='ACTIVE')return res.status(400).json({error:'Active consent not found.'});r.status='REVOKED';r.revokedAt=now();audit('CONSENT_REVOKED',{requestId:r.id,patientId:r.patientId,requesterId:r.requesterId});write();res.json({ok:true,request:r})});
app.get('/api/access/:id',auth,(req,res)=>{expire();const r=db.requests.find(x=>x.id===req.params.id);if(!r)return res.status(404).json({error:'Consent not found'});if(r.requesterId!==req.user.userId||r.status!=='ACTIVE')return res.status(403).json({error:'ACCESS DENIED — patient consent is not active.'});const patient=user(r.patientId);const profile=patient?.profile||{};const records=(r.categories||[]).map(category=>{let value='Authorized category';if(['Medical History','Diagnoses','Family History','Surgical History','Hospitalization History'].includes(category))value=(profile.conditions||[]).join(', ')||'No profile details available';if(category==='Allergies')value=(profile.allergies||[]).join(', ')||'No allergies recorded';if(category==='Medications')value=(profile.medications||[]).join(', ')||'No medications recorded';if(category.startsWith('Wearable'))value='Wearable data available only if the patient connected and approved this category.';return {category,value}});audit('AUTHORIZED_ACCESS',{requestId:r.id,patientId:r.patientId,requesterId:req.user.userId});write();res.json({ok:true,access:{requestId:r.id,requesterName:r.requesterName,requesterOrg:r.requesterOrg,categories:r.categories,conditions:r.conditions,purpose:r.purpose,startsAt:r.startsAt,expiresAt:r.expiresAt,records,message:'Access granted by active patient consent. Only the categories listed here are authorized.'}})});


function chatAllowed(encounterId,userId){
  const e=db.encounters.find(x=>x.id===encounterId);
  if(!e || (e.patientId!==userId && e.requesterId!==userId)) return false;
  return db.requests.some(r=>r.encounterId===encounterId && ['PROFILE_APPROVED','PAYMENT_PENDING_PATIENT','PAYMENT_PENDING_REQUESTER','ACTIVE'].includes(r.status));
}
app.get('/api/chat/:encounterId',auth,(req,res)=>{
  if(!chatAllowed(req.params.encounterId,req.user.userId)) return res.status(403).json({error:'Chat unlocks after the patient approves a consent request.'});
  const messages=db.chats.filter(m=>m.encounterId===req.params.encounterId).slice(-100);
  res.json({ok:true,messages});
});
app.post('/api/chat/:encounterId',auth,(req,res)=>{
  if(!chatAllowed(req.params.encounterId,req.user.userId)) return res.status(403).json({error:'Chat unlocks after the patient approves a consent request.'});
  const text=String(req.body?.text||'').trim();
  if(!text) return res.status(400).json({error:'Enter a message.'});
  const e=db.encounters.find(x=>x.id===req.params.encounterId);
  const msg={id:id('MSG'),encounterId:e.id,senderId:req.user.userId,senderRole:req.user.role,senderName:req.user.name,text,createdAt:now()};
  db.chats.push(msg); write(); res.json({ok:true,message:msg});
});

function healthAiAnswer(question, history=[]){
  const q=String(question||'').trim();
  const lower=q.toLowerCase();
  const prior=(Array.isArray(history)?history:[]).filter(x=>x&&x.role&&x.text).slice(-8);
  const lastUser=prior.filter(x=>x.role==='user').at(-1)?.text||'';
  const urgent=['chest pain','trouble breathing','difficulty breathing','shortness of breath','stroke','face droop','severe bleeding','unconscious','seizure lasting','suicidal','kill myself','overdose'].some(x=>lower.includes(x));
  if(urgent) return `This may need urgent medical attention. If symptoms are severe or sudden—such as chest pain, major breathing difficulty, signs of stroke, uncontrolled bleeding, loss of consciousness, an ongoing seizure, overdose, or thoughts of self-harm—seek emergency care now or contact your local emergency service. I can give general information, but I cannot safely diagnose an emergency in chat.`;

  const topic = (patterns) => patterns.find(([keys])=>keys.some(k=>lower.includes(k)));
  const topics = [
    [['hypertension','high blood pressure'], 'blood pressure', [
      'High blood pressure often causes no obvious symptoms. General steps include checking BP regularly, taking prescribed treatment consistently, limiting excess sodium, staying active, and keeping follow-up appointments.',
      'For hypertension, home BP readings can be useful when taken correctly and recorded over time. Treatment decisions depend on the readings, other conditions, medicines, and overall cardiovascular risk.',
      'If you are asking about hypertension, the key pieces are the actual BP readings, how they were measured, current medicines, and whether there are symptoms. A clinician can use those details to decide what should happen next.'
    ]],
    [['diabetes','blood sugar','glucose'], 'blood sugar/diabetes', [
      'Diabetes management commonly combines glucose monitoring, prescribed medicines when needed, balanced meals, physical activity, and regular follow-up. Targets differ between people.',
      'For blood-sugar questions, useful context includes whether the reading was fasting or after a meal, the actual value, symptoms, diabetes type, and current medicines.',
      'A single glucose result does not tell the whole story. Trends, HbA1c, timing of meals, medicines, and symptoms can all matter.'
    ]],
    [['headache','migraine'], 'headache', [
      'Headaches have many possible causes. Track when they start, severity, duration, triggers, sleep, hydration, medicines, and associated symptoms.',
      'For a recurring headache, keeping a simple diary of timing, location, severity, triggers, sleep, food, and medicines can help a clinician identify patterns.',
      'A sudden severe “worst headache,” new neurological symptoms, fever with a stiff neck, or a headache after significant head injury needs urgent assessment.'
    ]],
    [['fever','temperature'], 'fever', [
      'Fever can occur with infections and other conditions. Rest and fluids may help mild illness, while persistent or concerning fever should be assessed.',
      'When discussing a fever, the temperature, duration, age, associated symptoms, recent exposures, and medicines taken are useful details.',
      'Seek prompt medical care for fever with confusion, significant breathing difficulty, severe weakness, dehydration, stiff neck, or other rapidly worsening symptoms.'
    ]],
    [['cough','cold','flu','sore throat'], 'respiratory symptoms', [
      'Cough and cold symptoms can come from infections, allergies, asthma, reflux, and other causes. Hydration and rest may help mild illness.',
      'For a cough, useful details include how long it has lasted, whether it is dry or productive, fever, wheezing, breathing difficulty, smoking exposure, and medicines.',
      'Breathing difficulty, blue lips, chest pain, coughing blood, or rapidly worsening symptoms should be assessed promptly.'
    ]],
    [['stomach','abdominal pain','diarrhea','vomit','vomiting','nausea'], 'digestive symptoms', [
      'Digestive symptoms have many causes. Hydration is especially important with vomiting or diarrhea, and the duration and severity help determine whether assessment is needed.',
      'For stomach symptoms, note the location of pain, timing, vomiting, bowel changes, fever, blood, recent food or travel, and medicines.',
      'Severe or localized abdominal pain, blood in vomit or stool, persistent vomiting, fainting, or signs of dehydration warrant medical assessment.'
    ]],
    [['sleep','insomnia','sleeping'], 'sleep', [
      'A consistent sleep/wake schedule, a dark quiet room, limiting late caffeine, and reducing stimulating screen use before bed can help many people sleep better.',
      'For persistent insomnia, it helps to look at bedtime/wake time, naps, caffeine, medicines, stress, snoring, and daytime sleepiness.',
      'Loud snoring with pauses in breathing, severe daytime sleepiness, or persistent sleep problems are good reasons to discuss the issue with a clinician.'
    ]],
    [['anxiety','panic','stress'], 'anxiety/stress', [
      'Stress and anxiety can cause physical symptoms such as a racing heart, sweating, muscle tension, and poor sleep. Breathing exercises, activity, social support, and professional help can be useful.',
      'If anxiety keeps interfering with sleep, work, study, or daily life, it is worth discussing with a mental-health professional or clinician.',
      'If anxiety is accompanied by thoughts of self-harm or feeling unable to stay safe, seek urgent support rather than relying on an AI chat.'
    ]],
    [['depression','sad','low mood'], 'mood', [
      'Depression can affect mood, sleep, appetite, concentration, energy, and daily functioning. A clinician can assess symptoms and discuss appropriate support.',
      'If low mood has persisted for weeks or is affecting normal life, consider speaking with a qualified mental-health professional.',
      'If you are having thoughts of self-harm or feel unsafe, seek immediate support from local emergency or crisis services and someone you trust.'
    ]],
    [['exercise','workout','fitness'], 'exercise', [
      'For many adults, gradually increasing regular physical activity is beneficial. The right intensity depends on fitness, age, health conditions, and medications.',
      'A practical starting point is consistent, manageable activity rather than sudden intense workouts. Stop and seek medical advice for concerning symptoms such as chest pain or fainting.',
      'If you have a known heart, lung, joint, or metabolic condition, your clinician can help tailor exercise intensity safely.'
    ]],
    [['diet','food','nutrition'], 'nutrition', [
      'A balanced eating pattern generally includes vegetables, fruits, whole grains, protein sources, and appropriate portions while limiting excess salt, added sugars, and highly processed foods.',
      'The best diet advice depends on the goal and medical context. Conditions such as diabetes, kidney disease, hypertension, or food allergies may require different priorities.',
      'If you tell me the health condition and what you normally eat, I can help you identify general nutrition questions to discuss with a clinician or dietitian.'
    ]],
    [['medicine','medication','tablet','drug','dose','dosage'], 'medicines', [
      'Take medicines exactly as prescribed unless a clinician tells you otherwise. Do not start, stop, double, or combine medicines based only on an AI response.',
      'Medication questions depend heavily on the exact medicine, dose, timing, age, allergies, kidney/liver function, and other medicines or supplements.',
      'If you give me the medicine name and what you want to know—such as common uses, general side effects, or questions to ask your pharmacist—I can explain general information.'
    ]],
    [['ecg','ekg','electrocardiogram'], 'ECG/EKG', [
      'An ECG records the heart’s electrical activity. Clinicians use it to look for rhythm problems and other electrical patterns.',
      'An ECG result should be interpreted in context with symptoms, history, medications, and the actual tracing or clinician report; an AI chat should not diagnose from a number alone.',
      'If an ECG was ordered because of chest pain, fainting, severe breathlessness, or a new rapid/irregular heartbeat, follow the clinician’s advice promptly.'
    ]],
    [['blood test','blood tests','lab test','laboratory'], 'blood tests', [
      'Blood tests can measure different things such as blood counts, glucose, kidney function, liver enzymes, lipids, hormones, and markers of inflammation.',
      'A lab value cannot be interpreted reliably without the test name, result, units, reference range, timing, and clinical context.',
      'If you share the test name and result with its reference range, I can explain what that test generally measures and what questions to ask your clinician.'
    ]]
  ];

  const hit=topic(topics);
  let answer;
  if(hit){
    const variants=hit[2];
    let idx=0;
    for(let i=0;i<q.length;i++) idx=(idx+q.charCodeAt(i)*(i+1))%variants.length;
    answer=variants[idx];
  } else if(/^(hi|hello|hey|hii|good morning|good evening|good night)\b/i.test(q)) {
    answer='Hey! I can help with general health information. Tell me what you want to understand—symptoms, a condition, a test result, a medicine, nutrition, sleep, exercise, or what to ask your clinician.';
  } else if(/^(yes|yeah|yep|ok|okay|sure)\b/i.test(q) && lastUser) {
    answer=`Sure. Regarding “${lastUser.slice(0,120)}${lastUser.length>120?'…':''}”, tell me the specific part you want explained—possible causes, warning signs, tests, treatment questions, lifestyle, or what to discuss with a clinician.`;
  } else if(/\bwhat is\b|\bwhat does\b|\bmeaning of\b/i.test(lower)) {
    answer=`I can explain that in general terms. Tell me the exact health term, condition, test, or medicine you mean, and I’ll break down what it is, why it is used, common considerations, and when professional evaluation matters.`;
  } else if(/\bwhy\b|\bhow\b|\bshould i\b|\bcan i\b|\bis it\b|\bshould\b/i.test(lower)) {
    answer=`There can be several reasons and the safest answer depends on your specific situation. For a useful explanation, include the symptom or condition, how long it has been happening, your age range, relevant medicines or diagnoses, and any test results you have.`;
  } else {
    const variants=[
      'I can help with that as general health information. Tell me the symptom, condition, test, medicine, or health goal you are asking about, plus how long it has been relevant and any important diagnoses or medicines.',
      'I can work through that with you. Start with what you are experiencing or the exact medical term/result, then add timing, severity, age range, and relevant medicines or conditions. I’ll separate general information from warning signs.',
      'Let’s narrow it down. Tell me what you want to know about your health, what has changed, and whether you have any diagnosis, medication, or test result related to it. I can explain the general possibilities and questions to discuss with a clinician.'
    ];
    let idx=q.split('').reduce((a,c,i)=>(a+c.charCodeAt(0)*(i+1))%variants.length,0);
    answer=variants[idx];
  }
  return answer+' This chat provides general information and is not a diagnosis or a substitute for a clinician.';
}
app.post('/api/ai/health',auth,(req,res)=>{
  const question=String(req.body?.question||'').trim(); if(!question)return res.status(400).json({error:'Ask a health question.'});
  const history=Array.isArray(req.body?.history)?req.body.history:[];
  res.json({ok:true,answer:healthAiAnswer(question,history),mode:'ConsentVault Health AI · local safety-first assistant'});
});

app.get('/api/audit',auth,(req,res)=>{const relevant=db.audit.filter(a=>{const d=a.details||{};return req.user.role==='patient'?d.patientId===req.user.userId||['REQUEST_APPROVED','REQUEST_DENIED','CONSENT_REVOKED','CONSENT_EXPIRED','PAYMENT_MARKED_PAID','CONSENT_ACTIVATED'].includes(a.type):d.requesterId===req.user.userId||['REQUEST_CREATED','CONSENT_ACTIVATED','AUTHORIZED_ACCESS','CONSENT_EXPIRED','CONSENT_REVOKED','PAYMENT_MARKED_PAID'].includes(a.type)});res.json({audit:relevant.slice(-80).reverse()})});
if(process.env.NODE_ENV==='production'){app.use(express.static(path.join(__dirname,'dist')));app.get('*',(_,res)=>res.sendFile(path.join(__dirname,'dist','index.html')))}
app.listen(PORT,'0.0.0.0',()=>console.log(`ConsentVault API running on http://0.0.0.0:${PORT}`));
