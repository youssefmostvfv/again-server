'use strict';
/* Restore a daily backup. Stop the server first (Ctrl+C), then run:
   node restore.js data\backups\backup-2026-11-12.json                                  */
const fs=require('fs'),path=require('path');
const DATA=process.env.DATA_DIR||path.join(__dirname,'data'),file=process.argv[2];
if(!file||!fs.existsSync(file)){console.log('Usage: node restore.js <backup file>\nBackups are in:',path.join(DATA,'backups'));process.exit(1)}
const b=JSON.parse(fs.readFileSync(file,'utf8'));
if(!b.db||!b.db.state||!b.auth){console.log('This file is not a valid Again backup.');process.exit(1)}
const stamp=new Date().toISOString().replace(/[:.]/g,'-');
for(const f of ['state.json','auth.json'])if(fs.existsSync(path.join(DATA,f)))fs.copyFileSync(path.join(DATA,f),path.join(DATA,f+'.before-restore-'+stamp));
fs.writeFileSync(path.join(DATA,'state.json'),JSON.stringify(b.db));fs.writeFileSync(path.join(DATA,'auth.json'),JSON.stringify({creds:b.auth.creds||{},sessions:{}}));
console.log('Restored from',file,'\nThe previous data was kept next to it as *.before-restore-*.\nStart the server again.');
