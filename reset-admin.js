'use strict';
/* Emergency tool: sets a NEW random password for the main admin. Stop the server first (Ctrl+C), then run:  node reset-admin.js */
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const DATA=process.env.DATA_DIR||path.join(__dirname,'data');
const F_STATE=path.join(DATA,'state.json'),F_AUTH=path.join(DATA,'auth.json');
if(!fs.existsSync(F_STATE)){console.log('No data found in',DATA);process.exit(1)}
const db=JSON.parse(fs.readFileSync(F_STATE,'utf8')),auth=fs.existsSync(F_AUTH)?JSON.parse(fs.readFileSync(F_AUTH,'utf8')):{creds:{},sessions:{}};
const PWC='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
const adm=(db.state.usr||[]).find(u=>u.on&&u.roles.includes('admin'))||(db.state.usr||[]).find(u=>u.roles.includes('admin'));
if(!adm){console.log('No admin account exists.');process.exit(1)}
adm.on=1;let pw='';const b=crypto.randomBytes(24);for(let i=0;i<12;i++)pw+=PWC[b.readUInt16BE(i*2)%PWC.length];
const salt=crypto.randomBytes(16).toString('hex');
auth.creds[adm.id]={s:salt,h:crypto.scryptSync(pw,salt,32,{N:16384,r:8,p:1}).toString('hex')};
for(const k of Object.keys(auth.sessions||{}))if(auth.sessions[k].uid==adm.id)delete auth.sessions[k];
db.ver=(db.ver||0)+1;db.kv=db.kv||{};db.kv.usr=db.ver;
fs.writeFileSync(F_STATE,JSON.stringify(db));fs.writeFileSync(F_AUTH,JSON.stringify(auth));
console.log('\nAdmin account : '+adm.n+'\nUsername      : '+adm.un+'\nNEW password  : '+pw+'\n\nStart the server again and log in. Save this password.\n');
