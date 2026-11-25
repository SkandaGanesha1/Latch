import os,pty,select,subprocess,time,sys
from pathlib import Path
kind=sys.argv[1]; assert kind in ('writer', 'audit'), 'expected writer or audit'; root=Path(__file__).resolve().parent.parent; ifs=root/'qnx/build/nto-aarch64-le'/('latch_writer_test.ifs' if kind=='writer' else 'latch_audit_probe.ifs')
m,s=pty.openpty(); p=subprocess.Popen(['qemu-system-aarch64','-M','virt,virtualization=on,gic-version=2','-cpu','cortex-a76','-smp','4','-m','2048','-accel','tcg,thread=multi','-nographic','-serial','mon:stdio','-kernel',str(ifs)],stdin=s,stdout=s,stderr=s);os.close(s); log=bytearray()
def read(t, prompt=True):
 end=time.monotonic()+t; data=b''
 while time.monotonic()<end:
  if select.select([m],[],[],.1)[0]:
   try: b=os.read(m,65536)
   except OSError: break
   data+=b; log.extend(b)
   if prompt and data.endswith(b'# ') and (b'\n__AUDIT_DONE_' in data if kind=='audit' and b'latch_target_probe dump' in data else True): break
 return data.decode(errors='replace')
def cmd(c,t=5):
 os.write(m,c.encode()+b'\n'); return read(t)
try:
 boot=read(90); print('BOOT_PROMPT',boot.endswith('# '))
 if not boot.endswith('# '): raise RuntimeError('boot failed')
 if kind=='writer':
  start=cmd('/proc/boot/latch_target_probe hold /dev/latch/proposal &'); print('START',start)
  holder=read(3,False); print('HOLDER',holder); assert 'PROBE_OPEN success' in start + holder
  compete=cmd('/proc/boot/latch_target_probe try /dev/latch/proposal; echo COMPETE_RC=$?'); print('COMPETE',compete); assert 'COMPETE_RC=3' in compete
  closed=read(18,False); print('CLOSE',closed); assert 'PROBE_CLOSED' in closed
  reopen=cmd('/proc/boot/latch_target_probe try /dev/latch/proposal; echo REOPEN_RC=$?'); print('REOPEN',reopen); assert 'REOPEN_RC=0' in reopen and 'PROBE_OPEN success' in reopen
 else:
  time.sleep(45)
  status=cmd('/proc/boot/latchctl status',5); print('STATUS',status); assert 'Proposals Received   : 235' in status
  print('GUEST',cmd('/proc/boot/latchctl console',5))
  for name in ('policy','errors','unused'):
   result=cmd('/proc/boot/latch_target_probe dump /dev/secpolgenerate/'+name+'; echo __AUDIT_DONE_$?',30); print('BEGIN_'+name,result,'END_'+name); assert '\n__AUDIT_DONE_0' in result.replace('\r',''); contents=result.replace('\r','').split('\n',1)[1].split('__AUDIT_DONE_0',1)[0]; (root/'qnx/build'/('secpolgenerate-'+name+'.txt')).write_text(contents)
finally:
 p.terminate()
 try:p.wait(timeout=3)
 except subprocess.TimeoutExpired:p.kill()
 os.close(m)
 (root/'qnx/build'/('target_'+kind+'_raw.log')).write_bytes(log)
