package browser

import (
	"strconv"
	"strings"
)

// consolePage returns the self-contained canvas viewer served at a session root.
// It opens the streaming WebSocket, paints incoming JPEG frames to a canvas, and
// forwards mouse/keyboard as JSON. The canvas backing store AND the input
// coordinate mapping are sized to (w,h) — the gateway's render dimensions — so
// the page stays correct at whatever resolution GUARDRAIL_ISOLATION_WIDTH/HEIGHT
// select; the canvas is then CSS-scaled to fit the viewport. No device markup
// ever reaches this page — only pixels.
func consolePage(sid string, w, h int64) string {
	return strings.NewReplacer(
		"__SID__", sid,
		"__DEV_W__", strconv.FormatInt(w, 10),
		"__DEV_H__", strconv.FormatInt(h, 10),
	).Replace(consoleTmpl)
}

const consoleTmpl = `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GuardRail Session</title>
<style>
 html,body{margin:0;height:100%;background:#0b1220;overflow:hidden}
 #wrap{position:fixed;inset:0;display:flex;align-items:center;justify-content:center}
 #screen{background:#000;max-width:100%;max-height:100%;box-shadow:0 0 40px rgba(0,0,0,.6);cursor:default;outline:none}
 #status{position:fixed;top:8px;left:50%;transform:translateX(-50%);color:#9fb0c8;
   font:13px system-ui;background:rgba(15,23,42,.9);padding:6px 12px;border-radius:6px;z-index:5}
 #paste{position:fixed;right:10px;bottom:10px;z-index:6;font:12px system-ui;color:#cbd5e1;
   background:rgba(15,23,42,.92);border:1px solid #334155;border-radius:6px;padding:6px 10px;cursor:pointer}
 #paste:hover{background:#1e293b;color:#fff}
 #paste:focus-visible{outline:2px solid #38bdf8;outline-offset:2px}
 #dlgwrap{position:fixed;inset:0;z-index:10;display:none;align-items:center;justify-content:center;
   background:rgba(2,6,23,.55)}
 #dlg{max-width:420px;width:calc(100% - 32px);background:#0f172a;border:1px solid #334155;
   border-radius:10px;padding:16px;font:14px system-ui;color:#e2e8f0;box-shadow:0 20px 50px rgba(0,0,0,.5)}
 #dlgk{font:11px ui-monospace,monospace;text-transform:uppercase;letter-spacing:.08em;color:#94a3b8}
 #dlgm{margin:8px 0 12px;line-height:1.45;white-space:pre-wrap;word-break:break-word}
 #dlgi{width:100%;box-sizing:border-box;margin-bottom:12px;padding:7px 9px;border-radius:6px;
   border:1px solid #334155;background:#020617;color:#e2e8f0;font:13px system-ui}
 #dlgb{display:flex;gap:8px;justify-content:flex-end}
 #dlgb button{font:13px system-ui;padding:6px 14px;border-radius:6px;cursor:pointer;border:1px solid #334155;
   background:#1e293b;color:#e2e8f0}
 #dlgok{background:#0ea5e9;border-color:#0ea5e9;color:#04202e;font-weight:600}
</style></head><body>
<div id="wrap"><canvas id="screen" width="__DEV_W__" height="__DEV_H__" tabindex="0"></canvas></div>
<div id="status">Connecting to session…</div>
<button id="paste" type="button" title="Paste your clipboard into the device (Ctrl+V goes to your own browser, not the device)">Paste clipboard</button>
<div id="dlgwrap" role="dialog" aria-modal="true" aria-labelledby="dlgm">
 <div id="dlg">
  <div id="dlgk">Message from device</div>
  <div id="dlgm"></div>
  <input id="dlgi" type="text" />
  <div id="dlgb"><button id="dlgno" type="button">Cancel</button><button id="dlgok" type="button">OK</button></div>
 </div>
</div>
<script>
(function(){
 var DEV_W=__DEV_W__, DEV_H=__DEV_H__;
 var cv=document.getElementById('screen'), cx=cv.getContext('2d');
 var st=document.getElementById('status');
 var proto=location.protocol==='https:'?'wss:':'ws:';
 var base=location.pathname.replace(/\/+$/,'');
 var ws=new WebSocket(proto+'//'+location.host+base+'/__ws__');
 ws.binaryType='arraybuffer';
 ws.onopen=function(){ st.textContent='Connected'; setTimeout(function(){st.style.display='none';},1200); cv.focus(); };
 ws.onclose=function(){ st.style.display='block'; st.textContent='Session ended'; };
 ws.onerror=function(){ st.style.display='block'; st.textContent='Connection error'; };
 /* Painting is coalesced to the display refresh, newest-wins. Frames can arrive
    faster than the screen repaints (or faster than a JPEG decodes); decoding one
    per message would put the main thread to work painting stale frames it then
    immediately overdraws, which is felt as lag. So keep only the most recent
    frame, decode at most one at a time, and paint at most once per animation
    frame — the operator always sees the freshest frame the instant the display
    can show it, and superseded frames cost nothing. */
 var pending=null;    // newest undecoded frame; a later one replaces it
 var decoding=false;  // a createImageBitmap is in flight
 var scheduled=false; // a rAF paint is already queued
 function schedule(){ if(!scheduled){ scheduled=true; requestAnimationFrame(paint); } }
 function paint(){
   scheduled=false;
   if(pending===null||decoding) return;
   var buf=pending; pending=null; decoding=true;
   createImageBitmap(new Blob([buf],{type:'image/jpeg'})).then(function(bmp){
     cx.drawImage(bmp,0,0,DEV_W,DEV_H); bmp.close&&bmp.close();
   }).catch(function(){}).then(function(){
     decoding=false;
     if(pending!==null) schedule(); // a newer frame landed mid-decode — show it next
   });
 }
 ws.onmessage=function(ev){
   // Text = a notification about the session; binary = a frame of the device.
   if(typeof ev.data==='string'){ onNote(ev.data); return; }
   pending=ev.data; // discard any earlier undrawn frame; only the newest matters
   schedule();
 };
 function send(o){ if(ws.readyState===1) ws.send(JSON.stringify(o)); }

 /* Device dialogs. The device's alert/confirm/prompt runs in the browser on the
    server, so the operator would never see it — and until it is answered the
    page is blocked and the screen simply stops updating. Show it here and send
    the answer back. */
 var dw=document.getElementById('dlgwrap'), dm=document.getElementById('dlgm'),
     di=document.getElementById('dlgi'), dk=document.getElementById('dlgk'),
     dok=document.getElementById('dlgok'), dno=document.getElementById('dlgno');
 function onNote(raw){
   var n; try{ n=JSON.parse(raw); }catch(e){ return; }
   if(n.t!=='dialog') return;
   dm.textContent=n.message||'';
   dk.textContent=n.kind==='beforeunload'?'Leave this page?':'Message from device';
   var isPrompt=n.kind==='prompt';
   di.style.display=isPrompt?'block':'none';
   di.value=n['default']||'';
   // An alert has only one outcome, so offering "Cancel" would invent a choice
   // the device never gave.
   dno.style.display=(n.kind==='alert')?'none':'inline-block';
   dw.style.display='flex';
   (isPrompt?di:dok).focus();
 }
 function answer(ok){
   if(dw.style.display==='none') return;
   dw.style.display='none';
   send({t:'d',ok:ok,text:ok&&di.style.display!=='none'?di.value:''});
   cv.focus();
 }
 dok.addEventListener('click',function(){ answer(true); });
 dno.addEventListener('click',function(){ answer(false); });
 di.addEventListener('keydown',function(e){ e.stopPropagation();
   if(e.key==='Enter'){ answer(true); } if(e.key==='Escape'){ answer(false); } });
 dw.addEventListener('keydown',function(e){ e.stopPropagation();
   if(e.key==='Escape'&&dno.style.display!=='none'){ answer(false); } });

 /* Paste. The operator's own Ctrl+V targets this page, not the device being
    streamed, so it silently does nothing. This reads the clipboard on a real
    click (which is what the browser requires) and inserts it server-side. */
 var pb=document.getElementById('paste');
 function flash(msg){ st.style.display='block'; st.textContent=msg;
   setTimeout(function(){ st.style.display='none'; },1800); }
 pb.addEventListener('click',function(){
   if(!navigator.clipboard||!navigator.clipboard.readText){
     flash('This browser will not share the clipboard'); return;
   }
   navigator.clipboard.readText().then(function(txt){
     if(!txt){ flash('Clipboard is empty'); return; }
     send({t:'p',text:txt});
     cv.focus();
     flash('Pasted into the device');
   }).catch(function(){ flash('Clipboard permission denied'); });
 });
 function mods(e){ return (e.altKey?1:0)|(e.ctrlKey?2:0)|(e.metaKey?4:0)|(e.shiftKey?8:0); }
 function pt(e){ var r=cv.getBoundingClientRect();
   return {x:(e.clientX-r.left)*(DEV_W/r.width), y:(e.clientY-r.top)*(DEV_H/r.height)}; }
 /* Mouse-move throttling. The server dispatches each input event into the
    headless browser with a round-trip that costs about one frame (~16ms), so it
    absorbs ~60 events/sec. A moving mouse fires far more; sending every one
    queues them faster than they drain and the cursor — with any click or key
    stuck behind it — falls seconds behind. That IS the "screen share" lag. So
    coalesce: keep only the latest position and flush one move per animation
    frame. Discrete events (down/up/wheel/keys) send at once, flushing any pending
    move first so ordering holds. */
 var moveP=null, moveRAF=0;
 function sendMove(){ moveRAF=0; if(moveP===null) return;
   send({t:'m',e:'move',x:moveP.x,y:moveP.y,mod:moveP.mod}); moveP=null; }
 function flushMove(){ if(moveRAF) cancelAnimationFrame(moveRAF); sendMove(); }
 cv.addEventListener('mousemove',function(e){ var p=pt(e); moveP={x:p.x,y:p.y,mod:mods(e)};
   if(!moveRAF) moveRAF=requestAnimationFrame(sendMove); });
 cv.addEventListener('mousedown',function(e){ e.preventDefault(); cv.focus(); flushMove(); var p=pt(e); send({t:'m',e:'down',x:p.x,y:p.y,b:e.button,mod:mods(e)}); });
 window.addEventListener('mouseup',function(e){ flushMove(); var p=pt(e); send({t:'m',e:'up',x:p.x,y:p.y,b:e.button,mod:mods(e)}); });
 cv.addEventListener('contextmenu',function(e){ e.preventDefault(); });
 cv.addEventListener('wheel',function(e){ e.preventDefault(); var p=pt(e); send({t:'m',e:'wheel',x:p.x,y:p.y,dx:e.deltaX,dy:e.deltaY,mod:mods(e)}); },{passive:false});
 cv.addEventListener('keydown',function(e){ e.preventDefault(); var pr=e.key.length===1;
   send({t:'k',e:'down',key:e.key,code:e.code,kc:e.keyCode,text:pr?e.key:'',mod:mods(e)}); });
 cv.addEventListener('keyup',function(e){ e.preventDefault(); send({t:'k',e:'up',key:e.key,code:e.code,kc:e.keyCode,mod:mods(e)}); });
})();
</script></body></html>`
