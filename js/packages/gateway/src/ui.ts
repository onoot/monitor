/**
 * The operator dashboard, served by the analytics surface at `/`.
 *
 * A single self-contained page: no external assets, no build step, so it works
 * identically in the container and in a native run. It reads the session-gated
 * API of the same origin. All sensitive views -- checker, flags, artifacts,
 * addresses -- call endpoints that additionally require the admin role, and the
 * page hides those tabs for a team session.
 *
 * The HTML is embedded here rather than shipped as files so the built package
 * (`dist/`) is enough to run the whole surface; there is nothing to copy and
 * nothing for a wrong CWD to hide.
 */

export const UI_HTML = `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>monitor</title>
<style>
  :root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#e6edf3;--mut:#8b949e;--acc:#58a6ff;--ok:#3fb950;--bad:#f85149;--warn:#d29922;}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);font:13px/1.55 ui-monospace,Consolas,monospace}
  #app{display:flex;height:100vh;overflow:hidden}
  #side{width:226px;flex:0 0 226px;background:var(--panel);border-right:1px solid var(--line);padding:20px 14px;display:flex;flex-direction:column;gap:20px;height:100vh;overflow-y:auto}
  .brand{font-size:15px;letter-spacing:1px;padding:2px 9px}
  nav{display:flex;flex-direction:column;gap:3px}
  nav .ng{font-size:11px;text-transform:uppercase;letter-spacing:.9px;color:#c9d1d9;font-weight:600;padding:16px 9px 6px}
  nav button{text-align:left;width:100%;background:none;border:1px solid transparent;color:var(--mut);padding:8px 10px;cursor:pointer;border-radius:8px;font:inherit}
  nav button:hover{color:var(--fg);background:#1c2230}
  nav button.on{color:var(--fg);border-color:var(--line);background:#21262d}
  nav button:disabled{opacity:.35;cursor:default}
  #side-foot{margin-top:auto;padding-top:16px;border-top:1px solid var(--line);display:flex;flex-direction:column;gap:10px;font-size:12px}
  #who{display:flex;flex-direction:column;gap:8px;align-items:flex-start}
  #who .row2{display:flex;align-items:center;gap:8px}
  #main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh}
  #pagehead{padding:22px 26px 14px;border-bottom:1px solid var(--line)}
  #pagehead h2{margin:0;font-size:19px;font-weight:600;letter-spacing:.2px;line-height:1.3;padding-left:12px;border-left:3px solid var(--acc)}
  .pagehint{color:var(--mut);margin-top:7px;max-width:78ch;font-size:12px}
  .toolbar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:14px 26px;border-bottom:1px solid var(--line)}
  select,input{border:1px solid var(--line);background:var(--panel);color:var(--fg);padding:5px 8px;border-radius:6px}
  button.act{border:1px solid var(--line);background:#21262d;color:var(--fg);padding:6px 12px;border-radius:7px;cursor:pointer}
  button.act:hover{border-color:var(--acc)}
  table{width:100%;border-collapse:collapse;font-size:12px}
  th,td{padding:8px 12px;border-bottom:1px solid #21262d;text-align:left;vertical-align:top}
  th{color:var(--mut);position:sticky;top:0;background:var(--bg);z-index:1}
  td.mono{font-size:11.5px}
  .pill{display:inline-block;padding:1px 7px;border-radius:9px;font-size:10.5px;border:1px solid var(--line)}
  .p-forwarded{color:var(--ok)} .p-blocked,.p-throttled{color:var(--bad)} .p-refused{color:var(--mut)} .p-error{color:var(--warn)}
  .p-checker{color:#9a7cff} .p-team{color:var(--acc)} .p-admin{color:var(--ok)} .p-unknown{color:var(--mut)}
  .ok{color:var(--ok)} .bad{color:var(--bad)} .mut{color:var(--mut)}
  b.t{color:var(--acc)} b.f{color:#d29922}
  .wrap{flex:1;overflow:auto}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;padding:20px 26px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
  .card .mut{font-size:11.5px;text-transform:uppercase;letter-spacing:.6px;color:var(--acc);font-weight:600;margin-bottom:12px}
  .card div.break{padding:5px 0}
  .card .num{font-size:22px;font-weight:700}
  .login{max-width:340px;margin:14vh auto;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:28px}
  .login label{display:block;margin:14px 0 6px;color:var(--mut)}
  .login input{width:100%;padding:9px 11px}
  .login button{width:100%;margin-top:20px;padding:10px;cursor:pointer}
  #err{color:var(--bad);min-height:16px;margin-top:10px}
  .mono{font-family:inherit}
  .break{word-break:break-all}
  .muted{color:var(--mut)}
  .nowrap{white-space:nowrap}
  .pop{position:fixed;inset:0;background:rgba(1,4,9,.72);display:flex;align-items:center;justify-content:center;z-index:50}
  .pop .box{background:var(--panel);border:1px solid var(--line);border-radius:10px;max-width:860px;width:92%;max-height:84vh;overflow:auto;padding:20px}
  .pop .box h3{margin:0 0 12px}
  .pop .box .k{color:var(--mut);min-width:110px;display:inline-block}
  .pop .box .row{padding:6px 0;border-bottom:1px dashed #21262d}
  .pop .box pre{background:#0d1117;border:1px solid var(--line);border-radius:6px;padding:10px;white-space:pre-wrap;word-break:break-all;margin:6px 0 0}
  .f{cursor:pointer}
  .f:hover{text-decoration:underline}
  .graphwrap{overflow:auto;max-height:560px;border:1px solid var(--line);border-radius:8px;padding:10px;margin-top:8px}
  .graphwrap svg{display:block;user-select:none;-webkit-user-select:none}
  .hints{display:flex;flex-wrap:wrap;gap:6px 18px;margin:10px 0 4px;font-size:12px;color:var(--mut)}
  .hints b{color:var(--fg)}
  .legend{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:10px 0;font-size:12px;color:var(--mut)}
  .legend .lg-title{color:#c9d1d9;font-weight:600}
  .legend button.lg{display:inline-flex;align-items:center;gap:6px;background:#161b22;border:1px solid var(--line);color:var(--fg);border-radius:999px;padding:3px 11px;font-size:11.5px;cursor:pointer}
  .legend button.lg i{width:9px;height:9px;border-radius:2px;display:inline-block}
  .legend button.lg.off{opacity:.4;text-decoration:line-through}
  .legend .lg-sep{width:1px;height:14px;background:var(--line);margin:0 3px}
  .legend span.lg-static{display:inline-flex;align-items:center;gap:6px;background:#161b22;border:1px solid var(--line);color:var(--fg);border-radius:999px;padding:3px 11px;font-size:11.5px}
  .legend span.lg-static i{width:9px;height:9px;border-radius:2px;display:inline-block}
  .badge{display:inline-block;font-size:11px;border-radius:999px;padding:2px 9px;border:1px solid var(--line);color:var(--mut)}
  .badge.st-up{color:#3fb950;border-color:rgba(63,185,80,.55);background:rgba(63,185,80,.10)}
  .badge.st-down{color:var(--mut)}
  .badge.st-unknown{color:var(--mut);opacity:.6}
  @media (max-width:780px){#app{flex-direction:column;height:auto;overflow:visible}#side{width:100%;flex:none;flex-direction:row;flex-wrap:wrap;align-items:center;gap:12px}nav{flex-direction:row;flex-wrap:wrap}nav .ng{display:none}#side-foot{margin:0 0 0 auto;border:0;padding:0;flex-direction:row;align-items:center}#main{height:auto}.wrap{max-height:none}}
</style>
</head>
<body>
<div id="app" style="display:none">
  <aside id="side">
    <div class="brand">monitor</div>
    <nav id="nav">
      <div class="ng">Трафик</div>
      <button data-tab="overview" class="on">Обзор</button>
      <button data-tab="own">Наша</button>
      <button data-tab="teams">Команды</button>
      <button data-tab="checker" data-admin="1">Чекер</button>
      <div class="ng" data-admin="1">Находки</div>
      <button data-tab="flags" data-admin="1">Флаги</button>
      <button data-tab="artifacts" data-admin="1">Артефакты</button>
      <div class="ng" data-admin="1">Анализ</div>
      <button data-tab="reports" data-admin="1">Отчёты</button>
      <div class="ng" data-admin="1">Настройка</div>
      <button data-tab="addresses" data-admin="1">Адреса</button>
      <button data-tab="graph" data-admin="1">Граф</button>
      <button data-tab="services" data-admin="1">Сервисы</button>
      <button data-tab="accounts" data-admin="1">Аккаунты</button>
    </nav>
    <div id="side-foot"><div id="who"></div></div>
  </aside>
  <div id="main">
    <div id="pagehead"><h2 id="ptitle">Обзор</h2><div class="pagehint" id="phint"></div></div>
    <div class="toolbar" id="toolbar"></div>
    <div id="view" class="wrap"></div>
  </div>
</div>
<div id="pop" style="display:none"></div>
<div id="login" style="display:none">
  <div class="login">
    <h2 style="margin-top:0">Вход</h2>
    <label>логин</label><input id="u" autocomplete="username">
    <label>пароль</label><input id="p" type="password" autocomplete="current-password">
    <button class="act" id="signin">войти</button>
    <div id="err"></div>
  </div>
</div>
<script>
(function(){
  var TOK=localStorage.getItem('ad_token')||'';
  var ROLE=null; var TAB='overview';
  // The interactive path graph. 'topo' is the generated document, 'layout' the
  // operator's manual overlay, 'sel' the current selection and 'drag' the
  // in-progress mouse gesture; keeping them in one object means a redraw never
  // has to re-fetch to stay consistent with what is on screen.
  var G={topo:null,base:null,layout:null,sel:{},drag:null,hover:null,svg:null,saveTimer:null,hidden:{kinds:{},edges:{}}};
  var $=function(id){return document.getElementById(id)};
  // Set while a re-render of the current tab runs: the old content stays on
  // screen until the fresh data replaces it, and the scroll position survives.
  // Without it every refresh blanked the panel to "loading..." and jumped to
  // the top, which reads as constant flicker while the operator watches.
  var KEEP=false;
  var AUTO=true; try{AUTO=localStorage.getItem('ad_auto')!=='0'}catch(e){}
  var AUTO_TABS={overview:1,own:1,teams:1,checker:1,flags:1,artifacts:1};
  var AUTO_TIMER=null;
  function setView(html){
    var v=$('view');var st=v.scrollTop;
    // A repaint that would write byte-identical HTML only blinks: skip it. This
    // is what periodic "redraws" (whatever their source) turn into: visible
    // flicker with no data changing becomes a no-op.
    if(v.innerHTML===html){KEEP=false;return;}
    v.innerHTML=html;
    if(KEEP)v.scrollTop=st;
    KEEP=false;
  }
  function setHTML(el,html){
    if(!el||el.innerHTML===html)return;
    el.innerHTML=html;
  }
  function esc(s){
    return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/\\n/g,'<br>');
  }
  function api(path,opts){
    opts=opts||{};
    var headers={'accept':'application/json'};
    if(opts.body!==undefined)headers['content-type']='application/json';
    if(TOK)headers.authorization='Bearer '+TOK;
    return fetch(path,{method:opts.method||'GET',headers:headers,body:opts.body!==undefined?JSON.stringify(opts.body):undefined})
      .then(function(r){return r.json().catch(function(){return {}}).then(function(b){return {status:r.status,body:b}})});
  }
  function fetchText(path){
    return fetch(path,{headers:{authorization:'Bearer '+TOK,accept:'text/plain'}})
      .then(function(r){return r.text().then(function(t){return {status:r.status,text:t}})});
  }
  function saveText(name,text){
    var blob=new Blob([text],{type:'text/plain;charset=utf-8'});
    var url=URL.createObjectURL(blob);var a=document.createElement('a');
    a.href=url;a.download=name;document.body.appendChild(a);a.click();
    document.body.removeChild(a);URL.revokeObjectURL(url);
  }
  function isAdmin(){return ROLE&&ROLE.kind==='admin'}
  function pill(p){return '<span class="pill p-'+esc(p)+'">'+esc(p)+'</span>'}
  function teamSpan(team,own){var mark=own?' <span class="muted">наша</span>':'';if(!team)return own?'<span class="muted">наша</span>':'<span class="muted">-</span>';return '<span style="color:'+teamColor(team)+'">'+esc(team)+'</span>'+mark}
  function flagsCell(id,f){return (f||[]).map(function(x){return '<span class="break"><b class="f" data-p="'+esc(id)+'" title="подробнее">'+esc(x)+'</b></span>';}).join(' ')||'<span class="muted">-</span>'}
  function artsCell(a){return (a||[]).slice(0,6).map(function(x){return '<span class="pill"><b class="t">'+esc(x.type)+'</b> <span class="break">'+esc(x.value)+'</span></span>';}).join('<br>')||'<span class="muted">-</span>'}
  function openAttempt(id){
    if(!id)return;
    $('pop').innerHTML='<div class="pop"><div class="box"><h3>загрузка...</h3></div></div>';$('pop').style.display='block';
    api('/api/attempt?id='+encodeURIComponent(id)).then(function(r){
      if(r.status!==200){$('pop').innerHTML='<div class="pop"><div class="box"><div class="bad">'+esc(r.body.error||('HTTP '+r.status))+'</div></div></div>';return;}
      var a=r.body&&r.body.attempt;
      if(!a){$('pop').innerHTML='<div class="pop"><div class="box"><div class="bad">запись не найдена</div></div></div>';return;}
      var rows=[
        ['время',a.at],['ip',a.ip],['роль',a.principal],['команда',a.team||'-'],['сервис',a.service||'-'],
        ['метод',a.method],['host',a.host||'-'],['target',a.target],['исход',a.outcome],['статус',a.status==null?'-':a.status],
        ['байты',a.bytes],['длительность',a.durationMs+' мс'],['правила',(a.rules||[]).join(', ')||'-'],
        ['причина',a.reason]
      ];
      var head='<div class="row"><b class="k">'+esc(a.id.slice(0,14))+'</b> флаги: '+((a.flags||[]).map(function(x){return '<b class="f">'+esc(x)+'</b>'}).join(' ')||'-')+'</div>';
      var kv=rows.map(function(p){return '<div class="row"><span class="k">'+esc(p[0])+'</span>'+esc(p[1])+'</div>'}).join('');
      var hdrs=Object.keys(a.headers||{}).map(function(k){return '<div class="row"><span class="k">'+esc(k)+'</span>'+esc(a.headers[k])+'</div>'}).join('')||'<div class="muted">нет</div>';
      var htm='<div class="row"><span class="k">id</span><span class="mono">'+esc(a.id)+'</span></div>'+head+kv+
        '<div style="margin-top:8px"><span class="k">заголовки</span></div>'+hdrs+
        '<div style="margin-top:8px"><span class="k">тело</span><pre>'+esc(a.body!==undefined?a.body:'')+'</pre></div>';
      $('pop').innerHTML='<div class="pop"><div class="box"><h3>запрос</h3>'+htm+'<button class="act" style="margin-top:12px">закрыть</button></div></div>';
      $('pop').querySelector('button').onclick=function(){$('pop').style.display='none'};
    });
  }
  document.onclick=function(e){
    var t=e.target;
    if(!t||!t.closest)return;
    var f=t.closest('.f');
    if(f&&f.dataset.p){openAttempt(f.dataset.p);return;}
    if(t.closest('.pop')&&!t.closest('.box')){$('pop').style.display='none'}
  };
  function auth(){
    if(!TOK){$('login').style.display='block';$('app').style.display='none';return false;}
    $('app').style.display='flex';
    return true;
  }
  function requireTok(){
    if(!auth())return;
    // Resolves with whether a token is valid. It only sets ROLE and hides the
    // login box; it does NOT call render(), so render() -> requireTok() cannot
    // recurse into render() again. A recursive pair here restarted the whole
    // page for every /api/me round trip, which read as constant flicker.
    return api('/api/me').then(function(r){
      if(r.status===200){ROLE=r.body;$('login').style.display='none';$('app').style.display='flex';return true;}
      TOK='';localStorage.removeItem('ad_token');auth();return false;
    });
  }
  $('signin').onclick=function(){
    $('err').textContent='';
    var u=$('u').value,p=$('p').value;
    api('/api/login',{method:'POST',body:{login:u,password:p}}).then(function(r){
      if(r.status!==200){$('err').textContent=(r.body.error||'неверные данные');return;}
      TOK=r.body.token;ROLE=r.body.role;
      localStorage.setItem('ad_token',TOK);
      $('login').style.display='none';render();
    });
  };
  $('p').addEventListener('keydown',function(e){if(e.key==='Enter')$('signin').click()});

  function render(){
    renderNav();renderToolbar();
    requireTok().then(function(ok){
      if(ok){renderNav();who();renderTab(TAB)}
    });
  }
  function autoTick(){
    if(!AUTO||!TOK||document.hidden||!AUTO_TABS[TAB])return;
    renderTab(TAB);
  }
  function startAuto(){if(!AUTO_TIMER)AUTO_TIMER=setInterval(autoTick,5000);}
  function renderNav(){
    var admin=isAdmin();
    var hid=document.querySelectorAll('#nav [data-admin]');
    for(var i=0;i<hid.length;i++)hid[i].style.display=admin?'':'none';
    var buttons=document.querySelectorAll('#nav button');
    for(var j=0;j<buttons.length;j++){
      buttons[j].className=(buttons[j].dataset.tab===TAB)?'on':'';
    }
  }
  function renderToolbar(){
    var t=$('toolbar');t.innerHTML='';
    if(TAB==='own'||TAB==='teams'||TAB==='checker'){
      t.innerHTML='<span class="muted">фильтр</span>'+
        '<select id="rsrv"><option value="">все сервисы</option></select>'+
        (TAB==='teams'?'<select id="rteam"><option value="">все команды</option></select>':'')+
        '<select id="rout"><option value="">все исходы</option><option>forwarded</option><option>blocked</option><option>throttled</option><option>refused</option><option>error</option></select>'+
        '<button class="act" id="rgo">применить</button><span class="muted" id="rcnt"></span>';
      if(TAB==='teams')populateTeamFilter();
    }
    if(TAB==='artifacts')t.innerHTML='<select id="atyp"><option value="">все типы</option><option>md5</option><option>sha1</option><option>sha256</option><option>sha512</option><option>base64</option><option>hex</option><option>binary</option></select>'+
      '<button class="act" id="argo">применить</button>';
    if(TAB==='overview')t.innerHTML='<button class="act" id="oref">обновить</button><span class="muted" id="olast"></span>';
    if(TAB==='addresses')t.innerHTML='<span class="muted">кандидата можно пометить как чекера, админа или команду без правки файла</span>';
    if(TAB==='services')t.innerHTML='<span class="muted">сканировать:</span><input id="sdir" size="28" placeholder="каталог"><button class="act" id="sscan">найти</button><button class="act" id="sref">обновить</button>';
    if(TAB==='accounts')t.innerHTML='<span class="muted">учётные записи операторов (admin) и команд (team); изменения применяются сразу</span>';
    if(TAB==='own'||TAB==='teams'||TAB==='checker'||TAB==='flags'||TAB==='artifacts')t.innerHTML+='<button class="act" id="hclear" style="margin-left:auto">очистить историю</button>';
    if($('hclear'))$('hclear').onclick=function(){
      if(!confirm('очистить всю историю: ленту, счётчики и файлы захвата? маршруты, метки и граф останутся.'))return;
      var b=this;b.disabled=true;b.textContent='чищу...';
      api('/api/history',{method:'DELETE'}).then(function(r){
        if(r.status!==200)alert(((r.body&&r.body.error)||('HTTP '+r.status)));
        renderTab(TAB);
      });
    };
    if($('rgo'))$('rgo').onclick=function(){renderTab(TAB)};
    if($('argo'))$('argo').onclick=function(){renderTab('artifacts')};
    if($('oref'))$('oref').onclick=function(){renderTab('overview')};
    if($('sscan'))$('sscan').onclick=function(){var d=$('sdir').value; api('/api/discover',{method:'POST',body:{dir:d}}).then(function(r){renderServices(r.body)});};
    if($('sref'))$('sref').onclick=function(){renderTab('services')};
    if(AUTO_TABS[TAB]){
      t.insertAdjacentHTML('beforeend','<label class="muted" style="margin-left:auto;display:inline-flex;gap:6px;align-items:center;cursor:pointer"><input type="checkbox" id="auto"'+(AUTO?' checked':'')+'> авто 5с</label>');
      var au=$('auto');
      if(au)au.onchange=function(){AUTO=au.checked;try{localStorage.setItem('ad_auto',AUTO?'1':'0')}catch(e){}};
    }
    who();
  }
  function who(){
    $('who').innerHTML=ROLE?'<div class="row2"><span class="muted">роль</span> <span class="pill">'+esc(ROLE.kind)+'</span></div>'+
      '<div class="row2"><span class="muted">вход</span> <b>'+esc(ROLE.login)+'</b></div>'+
      '<button class="act" id="signout">выход</button>':'';
    var so=$('signout');
    if(so)so.onclick=function(){
      api('/api/logout',{method:'POST'}).then(function(){
        localStorage.removeItem('ad_token');
        location.reload();
      });
    };
  }

  function head(names){return '<tr>'+names.map(function(n){return '<th>'+esc(n)+'</th>'}).join('')+'</tr>'}
  function attemptRows(a){
    return a.map(function(x){
      return '<tr><td class="nowrap">'+esc(x.at)+'</td>'+
        '<td class="mono">'+esc(x.ip)+'</td>'+
        '<td>'+pill(x.principal)+'</td>'+
        '<td>'+teamSpan(x.team,x.own)+'</td>'+
        '<td class="nowrap">'+esc(x.service||'-')+'</td>'+
        '<td>'+esc(x.method)+'</td>'+
        '<td class="mono">'+esc(x.host||'-')+'</td>'+
        '<td class="break">'+esc(x.target)+'</td>'+
        '<td class="p-'+esc(x.outcome)+'">'+esc(x.outcome)+'</td>'+
        '<td>'+esc(x.status==null?'-':x.status)+'</td>'+
        '<td class="muted">'+esc((x.rules||[]).join(','))+'</td>'+
        '<td>'+flagsCell(x.id,x.flags)+'</td>'+
        '<td>'+artsCell(x.artifacts)+'</td></tr>';
    }).join('');
  }
  var TAB_INFO={
    overview:['Обзор','Сводка: сколько запросов прошло — по сервисам, ролям и командам. Живые находки — во вкладках «Флаги» и «Артефакты».'],
    own:['Наша команда','Только ваши запросы — адреса с пометкой «наша». Метку ставит админ во вкладке «Адреса».'],
    teams:['Команды','Запросы команд-соперников: роль team без пометки «наша». Отфильтруйте сервис, команду или исход сверху.'],
    checker:['Чекер','Трафик чекера — отдельный поток и папка data/checker. Здесь только адреса из списка checker.'],
    flags:['Флаги','Найденные флаги из тел, путей и заголовков. Клик по флагу открывает сам запрос.'],
    artifacts:['Артефакты','Хеши, кодировки и бинарные значения, найденные по форме. Тип можно отфильтровать сверху.'],
    reports:['Отчёты','Сгенерированные отчёты reports/<сервис>/ (статический разбор + живой трафик стенда) и дайджест всего стенда — компактный JSON/Markdown для нейросети.'],
    addresses:['Адреса','Метки адресов без правки файла: выберите роль; для команды — имя и галочку «наша», если это ваша команда. Применяются сразу и переживают рестарт.'],
    graph:['Граф','Карта путей из graph.yaml. Правки хранятся отдельно и не меняют сгенерированный документ.'],
    services:['Сервисы','Обнаружение, запуск и порты сервисов, которые маршрутизирует шлюз. Порт занимается только за шлюзом.'],
    accounts:['Аккаунты','Учётные записи: операторы (admin) и команды (team). Создание, смена роли и команды, сброс пароля, удаление. Хранятся в отдельном accounts.json; пароли — scrypt-хеши. Любой вошедший может сменить свой пароль.']
  };
  function setPageHead(){
    var info=TAB_INFO[TAB]||['',''];
    var t=$('ptitle');if(t)t.textContent=info[0];
    var h=$('phint');if(h)h.innerHTML=info[1];
  }
  function renderTab(tab){
    if(!auth())return;
    var prev=TAB;
    TAB=tab;renderNav();setPageHead();
    // Rebuild the filter bar only when the tab actually changes, so clicking
    // "применить" keeps the values the operator has just chosen.
    if(tab!==prev)renderToolbar();
    var v=$('view');
    var stay=tab===prev&&v.getAttribute('data-loaded')==='1'&&v.childElementCount>0;
    if(!stay)v.innerHTML='<span class="muted">загрузка...</span>';
    v.setAttribute('data-loaded','1');
    KEEP=stay;
    if(tab==='overview')loadOverview();
    else if(tab==='own')loadTraffic('own');
    else if(tab==='teams')loadTraffic('teams');
    else if(tab==='checker')loadTraffic('checker');
    else if(tab==='flags')loadFlags();
    else if(tab==='artifacts')loadArtifacts();
    else if(tab==='reports')loadReports();
    else if(tab==='addresses')loadAddresses();
    else if(tab==='graph')renderGraphTab();
    else if(tab==='services')renderTabServices();
    else if(tab==='accounts')loadAccounts();
  }
  function loadOverview(){
    api('/api/stats').then(function(r){
      if(r.status!==200){viewErr(r);return;}
      var h=r.body.history||{},s=r.body.storage||{};
      var cards=[
        ['попыток',h.attempts],
        ['dropped (буфер)',h.dropped],
        ['в файлах записано',s.written],
        ['в очереди',s.queued],
        ['ошибок записи',s.failures],
        ['отброшено (очередь)',s.dropped]
      ];
      var out='<div class="cards">'+cards.map(function(c){return '<div class="card"><div class="mut">'+esc(c[0])+'</div><div class="num">'+esc(c[1])+'</div></div>'}).join('')+'</div>';
      function kv(label,map){var k=Object.keys(map||{});return k.length===0?'<div class="muted">-</div>':'<div>'+k.map(function(x){return '<span class="pill">'+esc(x)+'</span> '+esc(map[x])}).join(' ')+'</div>'}
      out+='<div class="cards"><div class="card"><div class="mut">по сервисам</div>'+kv('',h.perService)+'</div>'+
        '<div class="card"><div class="mut">по ролям</div>'+kv('',h.perPrincipal)+'</div>'+
        '<div class="card"><div class="mut">по исходам</div>'+kv('',h.perOutcome)+'</div>'+
        '<div class="card"><div class="mut">по командам</div>'+kv('',h.perTeam)+'</div>'+
        '<div class="card"><div class="mut">хранилище</div><div class="muted">'+esc(s.dir||'-')+'</div>'+ (s.lastError?'<div class="bad">'+esc(s.lastError)+'</div>':'<div class="ok">без ошибок</div>')+'</div></div>';
      setView(out);
      if($('olast'))$('olast').textContent=' '+new Date().toLocaleTimeString();
    });
  }
  function trafficParams(tab){
    var p=[];
    if(tab==='own'){p.push('principal=team');p.push('own=true');}
    else if(tab==='teams'){p.push('principal=team');p.push('own=false');}
    else if(tab==='checker'){p.push('principal=checker');}
    var s=$('rsrv'),o=$('rout'),tm=$('rteam');
    if(s&&s.value)p.push('service='+encodeURIComponent(s.value));
    if(o&&o.value)p.push('outcome='+encodeURIComponent(o.value));
    if(tm&&tm.value)p.push('team='+encodeURIComponent(tm.value));
    return p.join('&');
  }
  function loadTraffic(tab){
    api('/api/history?limit=400&'+trafficParams(tab)).then(function(r){
      if(r.status!==200){viewErr(r);return;}
      var a=r.body.attempts||[];
      setView('<table>'+head(['время','ip','роль','команда','сервис','метод','host','target','исход','статус','правила','флаги','артефакты'])+attemptRows(a)+'</table>');
      if($('rcnt'))$('rcnt').textContent=' показ '+a.length;
    });
  }
  function populateTeamFilter(){
    var sel=$('rteam');if(!sel)return;
    api('/api/network').then(function(r){
      if(r.status!==200)return;
      var b=r.body||{},teams=b.teams||[],ownSet={};
      (b.ownTeams||[]).forEach(function(t){ownSet[t]=1});
      setHTML(sel,'<option value="">все команды</option>'+teams.map(function(t){return '<option value="'+esc(t)+'">'+esc(t)+(ownSet[t]?' (наша)':'')+'</option>'}).join(''));
    });
  }
  function loadFlags(){
    api('/api/flags?limit=400').then(function(r){
      if(r.status!==200){viewErr(r);return;}
      var f=r.body.flags||[];
      setView('<table>'+head(['флаг','сервис','роль','команда','ip','метод','host','target','исход','время'])+f.map(function(x){
        return '<tr><td class="break"><b class="f" data-p="'+esc(x.id)+'">'+esc(x.value)+'</b></td><td class="nowrap">'+esc(x.service||'-')+'</td><td>'+pill(x.principal)+'</td><td class="muted">'+esc(x.team||'-')+'</td><td class="mono">'+esc(x.ip)+'</td><td>'+esc(x.method)+'</td><td class="mono">'+esc(x.host||'-')+'</td><td class="break">'+esc(x.target)+'</td><td class="p-'+esc(x.outcome)+'">'+esc(x.outcome)+'</td><td class="nowrap">'+esc(x.at)+'</td></tr>';
      }).join('')+'</table>');
    });
  }
  function loadArtifacts(){
    var type=$('atyp')?$('atyp').value:'';
    api('/api/artifacts?limit=400'+(type?'&type='+encodeURIComponent(type):'')).then(function(r){
      if(r.status!==200){viewErr(r);return;}
      var a=r.body.artifacts||[];
      setView('<table>'+head(['тип','значение','сервис','роль','команда','ip','метод','host','target','исход','время'])+a.map(function(x){
        return '<tr><td><b class="t">'+esc(x.type)+'</b></td><td class="break">'+esc(x.value)+'</td><td class="nowrap">'+esc(x.service||'-')+'</td><td>'+pill(x.principal)+'</td><td class="muted">'+esc(x.team||'-')+'</td><td class="mono">'+esc(x.ip)+'</td><td>'+esc(x.method)+'</td><td class="mono">'+esc(x.host||'-')+'</td><td class="break">'+esc(x.target)+'</td><td class="p-'+esc(x.outcome)+'">'+esc(x.outcome)+'</td><td class="nowrap">'+esc(x.at)+'</td></tr>';
      }).join('')+'</table>');
    });
  }
  function loadReports(){
    api('/api/reports').then(function(r){
      if(r.status!==200){viewErr(r);return;}
      var list=(r.body&&r.body.reports)||[];
      var opts=list.map(function(x){
        return '<option value="'+esc(x.service)+'">'+esc(x.service)+' — '+(x.findings==null?'?':esc(x.findings))+' находок'+(x.generatedUtc?', '+esc(String(x.generatedUtc).slice(0,19)):'')+'</option>';
      }).join('');
      var out='<div class="card"><div class="mut">отчёт сервиса (reports/&lt;сервис&gt;)</div>'+
        (opts?'<select id="rpsel">'+opts+'</select> ':'<span class="muted">отчётов нет — запустите deploy\\stand-reports.ps1</span> ')+
        '<button class="act" id="rpmd"'+(opts?'':' disabled')+'>показать (md)</button> '+
        '<button class="act" id="rpjs"'+(opts?'':' disabled')+'>json</button> '+
        '<button class="act" id="rpsave"'+(opts?'':' disabled')+'>скачать</button></div>';
      out+='<div class="card"><div class="mut">дайджест всего стенда (для нейросети)</div>'+
        '<button class="act" id="dgmd">дайджест (md)</button> '+
        '<button class="act" id="dgjs">json</button> '+
        '<button class="act" id="dgsave">скачать</button></div>';
      out+='<pre id="rpbody" class="mono" style="white-space:pre-wrap;max-height:60vh;overflow:auto"></pre>';
      setView(out);
      var shown={name:'',mode:'md',text:''};
      function show(text){shown.text=text;var b=$('rpbody');if(b)b.textContent=text;}
      function loadService(mode){
        var s=$('rpsel');var name=s&&s.value;
        if(!name){show('нет отчётов');return;}
        shown.name=name;shown.mode=mode;
        var url=('/api/reports/'+encodeURIComponent(name)+(mode==='md'?'.md':''));
        fetchText(url).then(function(x){
          if(x.status!==200){show('HTTP '+x.status);return;}
          if(mode==='md'){show(x.text);return;}
          try{show(JSON.stringify(JSON.parse(x.text),null,2));}catch(e){show(x.text);}
        });
      }
      function loadDigest(mode){
        shown.name='digest';shown.mode=mode;
        fetchText('/api/digest'+(mode==='md'?'.md':'')).then(function(x){
          if(x.status!==200){show('HTTP '+x.status);return;}
          if(mode==='md'){show(x.text);return;}
          try{show(JSON.stringify(JSON.parse(x.text),null,2));}catch(e){show(x.text);}
        });
      }
      if($('rpmd'))$('rpmd').onclick=function(){loadService('md')};
      if($('rpjs'))$('rpjs').onclick=function(){loadService('json')};
      if($('rpsave'))$('rpsave').onclick=function(){if(shown.text)saveText(shown.name+'.'+(shown.mode==='md'?'md':'json'),shown.text)};
      if($('dgmd'))$('dgmd').onclick=function(){loadDigest('md')};
      if($('dgjs'))$('dgjs').onclick=function(){loadDigest('json')};
      if($('dgsave'))$('dgsave').onclick=function(){if(shown.text)saveText(shown.name+'.'+(shown.mode==='md'?'md':'json'),shown.text)};
      if(opts)loadService('md');
    });
  }
  function kindSelect(name, current){
    return '<select data-kind="'+name+'" class="mut">'+
      ['checker','admin','team'].map(function(k){return '<option value="'+k+'"'+(k===current?' selected':'')+'>'+k+'</option>'}).join('')+
      '</select>';
  }
  function labelIp(ip,kind,team,note,own){
    var body={cidr:ip,kind:kind};
    if(team)body.team=team;
    if(note)body.note=note;
    if(own)body.own=true;
    return api('/api/labels',{method:'POST',body:body}).then(function(r){if(r.status!==200)alert(r.body.error||('HTTP '+r.status));loadAddresses()});
  }
  function loadAddresses(){
    Promise.all([api('/api/ips'),api('/api/candidates'),api('/api/network')]).then(function(list){
      var ips=(list[0].body.byIp)||[],cand=(list[1].body.candidates)||[],net=list[2].body;
      var ov=(net.overrides)||[],eff=(net.effective)||[],teams=(net.teams)||[];
      var teamOpts=teams.map(function(t){return '<option value="'+esc(t)+'">'+esc(t)+'</option>'}).join('')||'<option value="alpha">alpha</option>';
      var out='<div class="cards"><div class="card"><div class="mut">кандидаты (unknown)</div>';
      out+=cand.map(function(c){
        return '<div class="break"><span class="pill">'+esc(c.ip)+'</span> <span class="muted">'+esc(c.attempts)+'</span> '+
          kindSelect('k'+esc(c.ip).replace(/\./g,'_'))+' '+
          '<select class="mut" data-team="t'+esc(c.ip).replace(/\./g,'_')+'">'+teamOpts+'</select> '+
          '<label class="muted"><input type="checkbox" data-own="o'+esc(c.ip).replace(/\./g,'_')+'"> наша</label> '+
          '<button class="act" data-sh="'+esc(c.ip)+'">применить</button></div>';
      }).join('')||'<div class="muted">нет</div>';
      out+='</div>';
      out+='<div class="card"><div class="mut">добавить вручную</div>'+
        '<input id="aip" size="34" placeholder="ip/cidr, ip/cidr, …" title="несколько адресов через запятую"> '+
        '<select id="akind"><option value="team">team</option><option value="admin">admin</option><option value="checker">checker</option></select> '+
        '<input id="ateam" size="10" placeholder="команда"> '+
        '<label class="muted"><input type="checkbox" id="aown"> наша</label> '+
        '<button class="act" id="aadd">добавить</button></div>';
      out+='<div class="card"><div class="mut">метки (из UI)</div>';
      out+=ov.map(function(x){
        return '<div class="break"><span class="pill">'+esc(x.cidr)+'</span> <span class="p-'+esc(x.kind)+'">'+esc(x.kind)+'</span> <span class="muted">'+esc(x.team||x.note||'-')+'</span>'+(x.own?' <span class="muted">наша</span>':'')+' <button class="act" data-del="'+esc(x.cidr)+'">убрать</button></div>';
      }).join('')||'<div class="muted">нет</div>';
      out+='</div>';
      if(isAdmin()){
        out+='<div class="card"><div class="mut">по IP</div>'+ips.map(function(t){
          return '<div class="break"><b>'+esc(t.ip)+'</b> <span class="muted">'+esc(t.principal)+'</span> req='+esc(t.requests)+' block='+esc(t.blocked)+' bytes='+esc(t.bytesSent)+'</div>';
        }).join('')+'</div>';
      }
      out+='<div class="card"><div class="mut">сеть (конфиг + метки)</div>'+eff.map(function(r){
        return '<div class="break"><span class="p-'+esc(r.kind)+'">'+esc(r.kind)+'</span> '+esc(r.cidr)+' <span class="muted">'+esc(r.team||r.note||'')+'</span>'+(r.own?' <span class="muted">наша</span>':'')+'</div>';
      }).join('')||'<div class="muted">-</div>'+'</div>';
      out+='</div>';
      $('view').innerHTML=out;
      var applies=$('view').querySelectorAll('button[data-sh]');
      for(var i=0;i<applies.length;i++){
        (function(b){
          b.onclick=function(){
            var ip=b.dataset.sh;
            var kind=$('view').querySelector('select[data-kind="k'+esc(ip).replace(/\./g,'_')+'"]').value;
            var team=$('view').querySelector('select[data-team="t'+esc(ip).replace(/\./g,'_')+'"]').value;
            var note=kind==='team'?team:null;
            var ownEl=$('view').querySelector('input[data-own="o'+esc(ip).replace(/\./g,'_')+'"]');
            labelIp(ip,kind,team,note,ownEl&&ownEl.checked);
          };
        })(applies[i]);
      }
      var dels=$('view').querySelectorAll('button[data-del]');
      for(var j=0;j<dels.length;j++){
        dels[j].onclick=function(){api('/api/labels?cidr='+encodeURIComponent(this.dataset.del),{method:'DELETE'}).then(function(){loadAddresses()})};
      }
      if($('aadd'))$('aadd').onclick=function(){
        var kind=$('akind').value,team=$('ateam').value.trim();
        var own=$('aown')&&$('aown').checked;
        var norm=$('aip').value.split(',').join(' ').split(String.fromCharCode(10)).join(' ').split(String.fromCharCode(9)).join(' ');
        var seen={},ips=[];
        norm.split(' ').forEach(function(tok){var a=tok.trim();if(a&&!seen[a]){seen[a]=1;ips.push(a);}});
        if(!ips.length){alert('нужен ip/cidr');return;}
        var b=this;b.disabled=true;b.textContent='добавляю...';
        (function step(i){
          if(i>=ips.length){loadAddresses();return;}
          var body={cidr:ips[i],kind:kind};
          if(team)body.team=team;
          if(kind==='team'&&team)body.note=team;
          if(own&&kind==='team')body.own=true;
          api('/api/labels',{method:'POST',body:body}).then(function(r){
            if(r.status!==200)alert(ips[i]+': '+(r.body.error||('HTTP '+r.status)));
            step(i+1);
          });
        })(0);
      };
    });
  }
  function addService(port,service,upstream){
    return api('/api/services',{method:'POST',body:{port:Number(port),service:service,upstream:upstream||undefined}}).then(function(r){
      if(r.status!==200)alert(r.body.error||('HTTP '+r.status));renderTabServices();
    });
  }
  function delService(port){
    return api('/api/services?port='+encodeURIComponent(port),{method:'DELETE'}).then(function(r){
      if(r.status!==200&&r.status!==404)alert(r.body.error||('HTTP '+r.status));renderTabServices();
    });
  }
  // Draws the paths from the generated YAML. The dashboard never invents a
  // node: it fetches /api/graph.yaml, parses it, and renders exactly what the
  // document says, so the picture and the file cannot disagree.
  function apiText(path){
    var headers={'accept':'text/yaml'};
    if(TOK)headers.authorization='Bearer '+TOK;
    return fetch(path,{headers:headers}).then(function(r){return r.text().then(function(x){return {status:r.status,text:x}})});
  }
  // The block-style YAML reader, matching the writer in topology.ts. Every
  // string the writer emits is JSON-quoted, so a quoted token is JSON.parse'd.
  function parseYaml(text){
    function leadingSpace(raw){
      var i=0;
      while(i<raw.length&&(raw.charAt(i)===' '||raw.charAt(i)==='\t'))i++;
      return i;
    }
    function isInt(tok){
      if(tok.length===0)return false;
      var i=tok.charAt(0)==='-'?1:0;
      if(i>=tok.length)return false;
      for(;i<tok.length;i++){var c=tok.charCodeAt(i);if(c<48||c>57)return false;}
      return true;
    }
    function isNum(tok){
      if(tok.length===0)return false;
      var i=tok.charAt(0)==='-'?1:0,dot=0;
      if(i>=tok.length)return false;
      for(;i<tok.length;i++){
        var ch=tok.charAt(i);
        if(ch==='.'){dot++;if(dot>1)return false;continue;}
        var c=tok.charCodeAt(i);if(c<48||c>57)return false;
      }
      return dot===1;
    }
    var lines=[];
    text.split(String.fromCharCode(10)).forEach(function(raw){
      if(raw.charAt(raw.length-1)===String.fromCharCode(13))raw=raw.slice(0,-1);
      var trimmed=raw.trim();
      if(trimmed===''||trimmed.charAt(0)==='#')return;
      lines.push({indent:leadingSpace(raw),text:trimmed});
    });
    var index=0;
    function scalar(tok){
      if(tok.charAt(0)==='"')return JSON.parse(tok);
      if(tok==='null'||tok==='~')return null;
      if(tok==='true')return true;
      if(tok==='false')return false;
      if(isInt(tok))return parseInt(tok,10);
      if(isNum(tok))return parseFloat(tok);
      return tok;
    }
    function block(indent){
      var at=lines[index];
      if(at&&at.indent===indent&&at.text.slice(0,2)==='- '){
        var list=[];
        while(index<lines.length&&lines[index].indent===indent&&lines[index].text.slice(0,2)==='- '){
          var content=lines[index].text.slice(2);index++;
          var colon=content.indexOf(': ');
          if(colon>0&&content.charAt(0)!=='"'){
            var item={};item[content.slice(0,colon)]=scalar(content.slice(colon+2));
            while(index<lines.length&&lines[index].indent>indent){
              var next=lines[index];var split=next.text.indexOf(': ');
              if(split<0)break;
              item[next.text.slice(0,split)]=scalar(next.text.slice(split+2));index++;
            }
            list.push(item);
          }else{list.push(scalar(content));}
        }
        return list;
      }
      var map={};
      while(index<lines.length&&lines[index].indent===indent&&lines[index].text.slice(0,2)!=='- '){
        var line=lines[index];var c=line.text.indexOf(':');
        var key=line.text.slice(0,c);var rest=line.text.slice(c+1).trim();index++;
        if(rest===''){map[key]=block(index<lines.length?lines[index].indent:indent+2);}
        else{map[key]=scalar(rest);}
      }
      return map;
    }
    return block(lines.length?lines[0].indent:0);
  }
  // Each team gets a stable colour hashed from its name, so attacker teams are
  // visually distinct in the graph, the legend and the tables.
  var TEAM_COLORS=['#9a7cff','#ff7b72','#3fb950','#d29922','#58a6ff','#39c5cf','#db61a2','#a5d6ff','#f0883e','#7ee787'];
  function teamColor(team){
    var key=String(team==null?'':team).replace(/^actor:team:/,'');
    if(!key)return TEAM_COLORS[0];
    var h=0;for(var i=0;i<key.length;i++)h=(h*31+key.charCodeAt(i))>>>0;
    return TEAM_COLORS[h%TEAM_COLORS.length];
  }
  function nodeColor(kind,id){
    if(kind==='team')return teamColor(id);
    if(kind==='actor')return '#9a7cff';
    if(kind==='gateway')return '#58a6ff';
    if(kind==='host')return '#3fb950';
    if(kind==='port')return '#d29922';
    if(kind==='candidate')return '#8b949e';
    return '#e6edf3';
  }
  // Legend and visibility filters. Each chip both explains the drawing and
  // toggles whether that kind is drawn, so a busy graph can be narrowed down.
  var GKIND=[['actor','актор'],['team','команда'],['gateway','шлюз'],['host','хост'],['port','порт'],['candidate','свободен'],['upstream','апстрим']];
  var EDGE_LEG=[['link','связи','#30363d'],['link-free','свободен','#8b949e'],['link-manual','вручную','#3fb950']];
  function edgeKind(e){if(e.manual)return 'link-manual';if(e.label==='свободен')return 'link-free';return 'link';}
  // Direction colours: the gateway is the fork of the diagram, so edges into it
  // (вход) and out of it (выход) are drawn in two distinct hues. Everything
  // else stays neutral; a manually drawn link keeps its green.
  var EDGE_IN='#58a6ff',EDGE_OUT='#d29922';
  function edgeColor(e){
    if(e.manual)return '#3fb950';
    if(e.label==='свободен')return '#8b949e';
    if(e.to==='gateway')return EDGE_IN;
    if(e.from==='gateway')return EDGE_OUT;
    return '#30363d';
  }
  function edgeMarker(e){
    var c=edgeColor(e);
    if(c===EDGE_IN)return 'arr-in';
    if(c===EDGE_OUT)return 'arr-out';
    if(c==='#3fb950')return 'arr-manual';
    return 'arr';
  }
  function teamName(n){var l=String((n&&(n.label||n.id))||'');if(l.indexOf('team ')===0)l=l.slice(5);return l;}
  function graphLegendHtml(){
    var hk=(G.hidden&&G.hidden.kinds)||{},he=(G.hidden&&G.hidden.edges)||{};
    var teams=((G.topo&&G.topo.nodes)||[]).filter(function(n){return n.kind==='team';});
    return '<span class="lg-title">показывать:</span>'+
      GKIND.map(function(g){return '<button class="lg'+(!hk[g[0]]?'':' off')+'" data-hk="'+g[0]+'"><i style="background:'+nodeColor(g[0])+'"></i>'+g[1]+'</button>';}).join('')+
      '<span class="lg-sep"></span>'+
      EDGE_LEG.map(function(g){return '<button class="lg'+(!he[g[0]]?'':' off')+'" data-he="'+g[0]+'"><i style="background:'+g[2]+'"></i>'+g[1]+'</button>';}).join('')+
      '<button class="lg" data-hall="1">все</button>'+
      '<span class="lg-sep"></span><span class="lg-title">направление:</span>'+
      '<span class="lg lg-static"><i style="background:'+EDGE_IN+'"></i>вход</span>'+
      '<span class="lg lg-static"><i style="background:'+EDGE_OUT+'"></i>выход</span>'+
      (teams.length?'<span class="lg-sep"></span><span class="lg-title">команды:</span>'+teams.map(function(n){return '<span class="lg lg-static"><i style="background:'+teamColor(n.id)+'"></i>'+esc(teamName(n))+'</span>';}).join(''):'');
  }
  function wireLegend(){
    var box=$('glegend');if(!box)return;
    var bs=box.querySelectorAll('button');
    for(var i=0;i<bs.length;i++){(function(b){
      b.onclick=function(){
        G.hidden=G.hidden||{kinds:{},edges:{}};G.hidden.kinds=G.hidden.kinds||{};G.hidden.edges=G.hidden.edges||{};
        if(b.dataset.hall){G.hidden.kinds={};G.hidden.edges={};}
        else if(b.dataset.hk){var k=b.dataset.hk;if(G.hidden.kinds[k])delete G.hidden.kinds[k];else G.hidden.kinds[k]=1;}
        else if(b.dataset.he){var e=b.dataset.he;if(G.hidden.edges[e])delete G.hidden.edges[e];else G.hidden.edges[e]=1;}
        box.innerHTML=graphLegendHtml();wireLegend();graphRender();
      };
    })(bs[i]);}
  }
  // Geometry shared by the static and the interactive renderers. Sizes are in
  // SVG user units, which equal CSS pixels because viewBox matches width/height.
  var GB={COL:210,BOXW:168,BOXY:46,STEP:66,PADX:24,PADY:30};
  // A link's identity, byte-identical to graphLayout.ts edgeKey(), so a link cut
  // here matches the one the server recorded.
  function gkey(from,to,label){return JSON.stringify([from,to,label===undefined?null:label]);}
  // Where a straight line leaves a node's box: the operator can drag a node
  // anywhere, so a left/right layer rule no longer holds.
  function boxEdge(cx,cy,dx,dy){
    var hw=GB.BOXW/2,hh=GB.BOXY/2;
    if(dx===0&&dy===0)return{x:cx,y:cy};
    var sx=dx===0?1e9:hw/Math.abs(dx),sy=dy===0?1e9:hh/Math.abs(dy),s=Math.min(sx,sy);
    return{x:cx+dx*s,y:cy+dy*s};
  }
  // The generated layout: one column per layer, vertically centred.
  function graphPositions(t){
    var nodes=t.nodes||[],layers={},maxL=0;
    nodes.forEach(function(n){var L=n.layer||0;(layers[L]=layers[L]||[]).push(n);if(L>maxL)maxL=L;});
    var maxCount=0;Object.keys(layers).forEach(function(k){if(layers[k].length>maxCount)maxCount=layers[k].length;});
    var height=Math.max(200,GB.PADY*2+Math.max(maxCount,1)*GB.STEP);
    var pos={};
    Object.keys(layers).forEach(function(k){
      var col=layers[k],startY=(height-col.length*GB.STEP)/2;
      col.forEach(function(n,i){pos[n.id]={x:GB.PADX+Number(k)*GB.COL,y:startY+i*GB.STEP+GB.STEP/2};});
    });
    return pos;
  }
  // The generated graph with the operator's overlay folded in: dragged
  // positions, cut links (removed) and drawn links (added).
  function graphModel(){
    var t=G.topo||{nodes:[],edges:[]},lay=G.layout||{positions:{},removed:[],added:[]};
    var hk=(G.hidden&&G.hidden.kinds)||{},he=(G.hidden&&G.hidden.edges)||{};
    var allNodes=t.nodes||[],pos=graphPositions(t);
    Object.keys(lay.positions||{}).forEach(function(id){if(pos[id]){pos[id].x=lay.positions[id].x;pos[id].y=lay.positions[id].y;}});
    var vis={};allNodes.forEach(function(n){if(!hk[n.kind])vis[n.id]=1;});
    var nodes=allNodes.filter(function(n){return vis[n.id];});
    var removed={};(lay.removed||[]).forEach(function(k){removed[k]=1;});
    var baseSet={};(t.edges||[]).forEach(function(e){baseSet[gkey(e.from,e.to,e.label)]=1;});
    var addedSet={};(lay.added||[]).forEach(function(e){addedSet[gkey(e.from,e.to,e.label)]=1;});
    var edges=[];
    (t.edges||[]).forEach(function(e){
      var k=gkey(e.from,e.to,e.label);if(removed[k])return;
      if(!vis[e.from]||!vis[e.to])return;
      if(he[edgeKind({label:e.label})])return;
      edges.push({from:e.from,to:e.to,label:e.label,key:k,manual:!!addedSet[k]});
    });
    (lay.added||[]).forEach(function(e){
      var k=gkey(e.from,e.to,e.label);
      if(removed[k]||baseSet[k]||!(pos[e.from]&&pos[e.to]))return;
      if(!vis[e.from]||!vis[e.to])return;
      if(he['link-manual'])return;
      edges.push({from:e.from,to:e.to,label:e.label,key:k,manual:true});
    });
    var width=320,height=200;
    nodes.forEach(function(n){var p=pos[n.id];if(!p)return;width=Math.max(width,p.x+GB.BOXW+GB.PADX);height=Math.max(height,p.y+GB.BOXY/2+GB.PADY);});
    return {t:t,lay:lay,pos:pos,edges:edges,nodes:nodes,totalNodes:allNodes.length,width:width,height:height};
  }
  function graphCurrent(id){
    var lp=(G.layout&&G.layout.positions&&G.layout.positions[id])||(G.base&&G.base[id])||{x:0,y:0};
    return {x:lp.x,y:lp.y};
  }
  function bandRect(){
    var d=G.drag;if(!d)return{x:0,y:0,w:0,h:0};
    return{x:Math.min(d.sx,d.x),y:Math.min(d.sy,d.y),w:Math.abs(d.x-d.sx),h:Math.abs(d.y-d.sy)};
  }
  function graphSvg(){
    var m=graphModel();
    var parts=['<defs>'+
      '<marker id="arr" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#8b949e"/></marker>'+
      '<marker id="arr-in" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="'+EDGE_IN+'"/></marker>'+
      '<marker id="arr-out" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="'+EDGE_OUT+'"/></marker>'+
      '<marker id="arr-manual" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#3fb950"/></marker>'+
      '</defs>'];
    m.edges.forEach(function(e){
      var a=m.pos[e.from],b=m.pos[e.to];if(!a||!b)return;
      var dx=b.x-a.x,dy=b.y-a.y,s=boxEdge(a.x,a.y,dx,dy),t2=boxEdge(b.x,b.y,-dx,-dy);
      var col=edgeColor(e),mid=edgeMarker(e);
      var dash=e.manual?' stroke-dasharray="6 4"':(e.label==='свободен'?' stroke-dasharray="5 4" stroke-opacity="0.55"':'');
      var d='M'+s.x+','+s.y+' L'+t2.x+','+t2.y;
      parts.push('<path data-edge="'+esc(e.key)+'" d="'+d+'" fill="none" stroke="'+col+'" stroke-width="'+(e.manual?1.6:1.3)+'"'+dash+' marker-end="url(#'+mid+')"/>');
      parts.push('<path data-edge="'+esc(e.key)+'" data-hit="1" d="'+d+'" fill="none" stroke="transparent" stroke-width="14"/>');
      if(e.label)parts.push('<text x="'+((s.x+t2.x)/2)+'" y="'+((s.y+t2.y)/2-4)+'" fill="'+(e.manual?'#3fb950':'#8b949e')+'" font-size="10" text-anchor="middle">'+esc(e.label)+'</text>');
    });
    if(G.drag&&G.drag.mode==='link'){
      var a2=m.pos[G.drag.from];
      if(a2){var sp=boxEdge(a2.x,a2.y,G.drag.x-a2.x,G.drag.y-a2.y);
        parts.push('<path d="M'+sp.x+','+sp.y+' L'+G.drag.x+','+G.drag.y+'" fill="none" stroke="#58a6ff" stroke-width="1.8" stroke-dasharray="6 4"/>');}
    }
    var sel=G.sel||{};
    (m.nodes||[]).forEach(function(n){
      var p=m.pos[n.id];if(!p)return;
      var c=nodeColor(n.kind,n.id),isSel=!!sel[n.id],isHover=G.hover===n.id;
      if(isSel)parts.push('<rect x="'+(p.x-3)+'" y="'+(p.y-GB.BOXY/2-3)+'" width="'+(GB.BOXW+6)+'" height="'+(GB.BOXY+6)+'" rx="10" fill="none" stroke="#58a6ff" stroke-width="2"/>');
      parts.push('<g data-node="'+esc(n.id)+'" style="cursor:move"><title>'+esc(n.detail)+'</title>'+
        '<rect x="'+p.x+'" y="'+(p.y-GB.BOXY/2)+'" width="'+GB.BOXW+'" height="'+GB.BOXY+'" rx="8" fill="#161b22" stroke="'+(isHover?'#58a6ff':c)+'" stroke-opacity="0.9" stroke-width="'+(isSel?2.6:1.4)+'"'+(n.kind==='candidate'?' stroke-dasharray="5 4"':'')+'/>'+
        '<text x="'+(p.x+10)+'" y="'+(p.y-3)+'" fill="#e6edf3" font-size="11.5">'+esc(n.label)+'</text>'+
        '<text x="'+(p.x+10)+'" y="'+(p.y+12)+'" fill="'+c+'" font-size="9.5" opacity="0.85">'+esc(n.kind)+'</text>'+
        '</g>');
    });
    if(G.drag&&G.drag.mode==='band'){
      var r=bandRect();
      parts.push('<rect x="'+r.x+'" y="'+r.y+'" width="'+r.w+'" height="'+r.h+'" fill="rgba(88,166,255,0.10)" stroke="#58a6ff" stroke-dasharray="4 4"/>');
    }
    return '<div class="mut" style="margin:2px 0 6px">обновлён '+esc(m.t.generatedAt||'')+' · узлов '+(m.totalNodes!==m.nodes.length?(m.nodes.length+'/'+m.totalNodes):m.nodes.length)+', связей '+m.edges.length+' · выделено '+Object.keys(sel).length+'</div>'+
      '<svg viewBox="0 0 '+m.width+' '+m.height+'" width="'+m.width+'" height="'+m.height+'" xmlns="http://www.w3.org/2000/svg">'+parts.join('')+'</svg>';
  }
  function graphRender(){
    var el=$('graph');if(!el)return;
    el.innerHTML=graphSvg();
    G.svg=el.querySelector('svg');
    el.onmousedown=graphDown;
  }
  function graphPoint(e){
    var r=G.svg.getBoundingClientRect();
    var w=(G.svg.viewBox&&G.svg.viewBox.baseVal&&G.svg.viewBox.baseVal.width)||r.width||1;
    var sc=r.width?w/r.width:1;
    return {x:(e.clientX-r.left)*sc,y:(e.clientY-r.top)*sc};
  }
  function graphSave(){
    if(G.saveTimer)clearTimeout(G.saveTimer);
    G.saveTimer=setTimeout(function(){
      if(!G.layout)return;
      api('/api/graph/layout',{method:'POST',body:G.layout}).then(function(r){
        var s=$('gstat');if(!s)return;
        s.textContent=r.status===200?('сохранено: позиций '+((r.body&&r.body.positions)||0)+', разорвано '+((r.body&&r.body.removed)||0)+', новых '+((r.body&&r.body.added)||0)):('ошибка сохранения: '+((r.body&&r.body.error)||r.status));
      });
    },200);
  }
  function graphAddEdge(from,to){
    var k=gkey(from,to,'вручную');
    var exists=(G.topo.edges||[]).some(function(b){return gkey(b.from,b.to,b.label)===k;});
    if(!exists&&G.layout.added)exists=G.layout.added.some(function(b){return gkey(b.from,b.to,b.label)===k;});
    if(exists)return;
    G.layout.added=G.layout.added||[];
    G.layout.added.push({from:from,to:to,label:'вручную'});
    graphSave();
  }
  function graphCutEdge(key){
    var added=G.layout.added||[],idx=-1;
    for(var i=0;i<added.length;i++){if(gkey(added[i].from,added[i].to,added[i].label)===key){idx=i;break;}}
    if(idx>=0){added.splice(idx,1);}
    else{G.layout.removed=G.layout.removed||[];if(G.layout.removed.indexOf(key)<0)G.layout.removed.push(key);}
    graphSave();
    graphRender();
  }
  function graphDown(e){
    if(!G.svg||e.button!==0)return;
    var el=e.target,nodeEl=el&&el.closest?el.closest('[data-node]'):null,edgeEl=el&&el.closest?el.closest('[data-edge]'):null;
    if(edgeEl&&e.altKey){e.preventDefault();graphCutEdge(edgeEl.getAttribute('data-edge'));return;}
    var p=graphPoint(e);
    if(nodeEl){
      var id=nodeEl.getAttribute('data-node');
      if(e.ctrlKey||e.metaKey){
        G.drag={mode:'link',from:id,sx:p.x,sy:p.y,x:p.x,y:p.y,moved:false};
      }else{
        if(e.shiftKey){if(G.sel[id])delete G.sel[id];else G.sel[id]=1;}
        else if(!G.sel[id]){G.sel={};G.sel[id]=1;}
        var start={};
        Object.keys(G.sel).forEach(function(k){var cur=graphCurrent(k);start[k]={x:cur.x,y:cur.y};});
        G.drag={mode:'move',sx:p.x,sy:p.y,start:start,moved:false};
      }
      e.preventDefault();graphRender();return;
    }
    var base={};
    if(e.shiftKey||e.ctrlKey||e.metaKey){Object.keys(G.sel).forEach(function(k){base[k]=1;});}
    G.sel=base;
    G.drag={mode:'band',sx:p.x,sy:p.y,x:p.x,y:p.y,base:base,moved:false};
    e.preventDefault();graphRender();
  }
  function graphMove(e){
    var d=G.drag;if(!d||!G.svg)return;
    var p=graphPoint(e),dx=p.x-d.sx,dy=p.y-d.sy;
    if(!d.moved&&(Math.abs(dx)>3||Math.abs(dy)>3))d.moved=true;
    if(d.mode==='move'&&d.moved){
      G.layout.positions=G.layout.positions||{};
      Object.keys(d.start).forEach(function(k){G.layout.positions[k]={x:Math.round(d.start[k].x+dx),y:Math.round(d.start[k].y+dy)};});
      graphRender();
    }else if(d.mode==='band'){
      d.x=p.x;d.y=p.y;
      var r=bandRect(),sel={};
      Object.keys(d.base).forEach(function(k){sel[k]=1;});
      (G.topo.nodes||[]).forEach(function(n){var cur=graphCurrent(n.id);if(cur.x>=r.x&&cur.x<=r.x+r.w&&cur.y>=r.y&&cur.y<=r.y+r.h)sel[n.id]=1;});
      G.sel=sel;graphRender();
    }else if(d.mode==='link'&&d.moved){
      d.x=p.x;d.y=p.y;
      var el=e.target,nodeEl=el&&el.closest?el.closest('[data-node]'):null;
      G.hover=nodeEl&&nodeEl.getAttribute('data-node')!==d.from?nodeEl.getAttribute('data-node'):null;
      graphRender();
    }
  }
  function graphUp(e){
    var d=G.drag;if(!d)return;
    G.drag=null;
    if(d.mode==='link'){
      if(d.moved){
        var el=e.target,nodeEl=el&&el.closest?el.closest('[data-node]'):null,to=nodeEl?nodeEl.getAttribute('data-node'):null;
        if(to&&to!==d.from)graphAddEdge(d.from,to);
      }else if(d.from){
        if(d.from in G.sel)delete G.sel[d.from];else G.sel[d.from]=1;
      }
    }else if(d.mode==='move'&&d.moved){
      graphSave();
    }
    G.hover=null;
    graphRender();
  }
  window.addEventListener('mousemove',graphMove);
  window.addEventListener('mouseup',graphUp);
  function drawGraph(){
    var el=$('graph');if(!el)return;
    el.innerHTML='<div class="muted">загрузка графа...</div>';
    Promise.all([apiText('/api/graph.yaml'),api('/api/graph/layout')]).then(function(rs){
      var r=rs[0],l=rs[1];
      if(r.status!==200){el.innerHTML='<div class="bad">'+esc((JSON.parse(r.text||'{}').error)||('HTTP '+r.status))+'</div>';return;}
      var t;try{t=parseYaml(r.text);}catch(e){el.innerHTML='<div class="bad">yaml: '+esc(e.message)+'</div>';return;}
      G.topo=t||{nodes:[],edges:[]};
      G.base=graphPositions(G.topo);
      G.layout=(l.status===200&&l.body&&l.body.positions)?l.body:{version:1,positions:{},removed:[],added:[]};
      G.sel={};
      graphRender();
      var s=$('gstat');if(s)s.textContent='';
    });
  }
  function graphReset(){
    G.layout={version:1,positions:{},removed:[],added:[]};
    G.sel={};
    api('/api/graph/layout',{method:'DELETE'}).then(function(){graphRender();});
  }
  function renderGraphTab(){
    var out='<div class="card" style="margin:12px"><div class="mut">граф путей (генерируется в graph.yaml; правки хранятся отдельно) <button class="act" id="gref">обновить</button> <button class="act" id="gyaml">показать yaml</button> <button class="act" id="greset">сбросить правки</button> <button class="act" id="gclean">очистить стенд</button> <span id="gstat" class="muted" style="margin-left:8px"></span></div>'+
      '<div class="hints">'+
      '<span><b>ЛКМ</b> по узлу — выбрать</span>'+
      '<span><b>Shift/Ctrl+клик</b> — добавить к выделению</span>'+
      '<span><b>тянуть узел</b> — переместить выбранные</span>'+
      '<span><b>тянуть по пустому</b> — рамка выделения</span>'+
      '<span><b>Ctrl+тянуть</b> от узла к узлу — новая связь</span>'+
      '<span><b>Alt+клик</b> по линии — разорвать связь</span>'+
      '</div>'+
      '<div id="glegend" class="legend"></div>'+
      '<div id="graph" class="graphwrap"></div><pre id="gyamlbox" style="display:none;max-height:340px;overflow:auto"></pre></div>';
    setView(out);
    var lg=$('glegend');if(lg)lg.innerHTML=graphLegendHtml();
    wireLegend();
    drawGraph();
    if($('gref'))$('gref').onclick=drawGraph;
    if($('gyaml'))$('gyaml').onclick=function(){
      var box=$('gyamlbox');
      if(box.style.display==='none'){box.innerHTML='<span class="muted">загрузка...</span>';box.style.display='block';apiText('/api/graph.yaml').then(function(r){box.textContent=r.text;});}
      else{box.style.display='none';}
    };
    if($('greset'))$('greset').onclick=function(){if(confirm('сбросить ручные правки графа?'))graphReset();};
    if($('gclean'))$('gclean').onclick=function(){
      if(!confirm('очистить весь стенд: маршруты, метки, граф и захваты?'))return;
      var b=this;b.disabled=true;b.textContent='чищу...';
      api('/api/state',{method:'DELETE'}).then(function(r){
        if(r.status!==200)alert(((r.body&&r.body.error)||('HTTP '+r.status)));
        renderGraphTab();
      });
    };
  }
  function renderServices(dis){
    var list=(dis.candidates)||[];
    var groups={};
    list.forEach(function(c){ (groups[c.group]=groups[c.group]||[]).push(c); });
    var out='<div class="cards">';
    if(dis.error)out+='<div class="bad">'+esc(dis.error)+'</div>';
    out+=Object.keys(groups).sort().map(function(g){
      var cs=groups[g];
      var body=cs.map(function(c){
        return '<div class="break"><span class="pill">:'+esc(c.publicPort)+'</span> <b>'+esc(c.service)+'</b> <span class="muted">'+esc(c.upstream||'')+'</span> '+
          '<button class="act" data-add="'+esc(c.publicPort)+'" data-svc="'+esc(c.service)+'" data-up="'+esc(c.upstream||'')+'">занять порт</button></div>';
      }).join('');
      return '<div class="card"><div class="mut">'+esc(g)+' <span class="badge st-unknown" data-st="'+esc(g)+'">…</span> <button class="act" data-launch="'+esc(g)+'">запустить</button> <button class="act" data-stop="'+esc(g)+'">остановить</button>'+(cs.length>1?' <button class="act" data-all="'+esc(g)+'">занять все ('+cs.length+')</button>':'')+'</div>'+body+'</div>';
    }).join('')||'<div class="muted">ничего не найдено</div>';
    out+='<div class="card"><div class="mut">ручное добавление</div>'+
      '<input id="mport" size="6" placeholder="порт"> <input id="msvc" size="14" placeholder="сервис"> <input id="mup" size="24" placeholder="upstream (опц.)"> '+
      '<button class="act" id="madd">добавить</button></div>';
    out+='<div class="card"><div class="mut">маршруты (активные)</div>';
    out+='<div id="aports"></div><div id="aroutes"></div></div>';
    out+='</div>';
    setView(out);
    function refreshStatus(){
      api('/api/services/status').then(function(r){
        var map={};((r.body&&r.body.groups)||[]).forEach(function(x){map[x.group]=x;});
        var bs=$('view').querySelectorAll('[data-st]');
        for(var i=0;i<bs.length;i++){
          var b=bs[i],g=b.dataset.st,s=map[g],up=!!(s&&s.running);
          b.className='badge '+(up?'st-up':'st-down');
          b.textContent=up?('запущен'+(s.containers>1?' · '+s.containers:'')):'не запущен';
          var lb=$('view').querySelector('[data-launch="'+g+'"]'),sb=$('view').querySelector('[data-stop="'+g+'"]');
          if(lb)lb.disabled=up;
          if(sb)sb.disabled=!up;
        }
      });
    }
    refreshStatus();
    var adds=$('view').querySelectorAll('button[data-add]');
    for(var i=0;i<adds.length;i++){
      adds[i].onclick=function(){addService(Number(this.dataset.add),this.dataset.svc,this.dataset.up)};
    }
    var alls=$('view').querySelectorAll('button[data-all]');
    for(var a=0;a<alls.length;a++){
      (function(btn){
        btn.onclick=function(){
          var cs=groups[btn.dataset.all]||[];
          (function occupy(i){
            if(i>=cs.length){renderTabServices();return;}
            addService(Number(cs[i].publicPort),cs[i].service,cs[i].upstream).then(function(){occupy(i+1)});
          })(0);
        };
      })(alls[a]);
    }
    var launches=$('view').querySelectorAll('button[data-launch]');
    for(var l=0;l<launches.length;l++){(function(btn){
      btn.onclick=function(){
        btn.disabled=true;btn.textContent='запускаю...';
        api('/api/services/launch',{method:'POST',body:{group:btn.dataset.launch}}).then(function(r){
          if(r.status!==200)alert(((r.body&&r.body.error)||('HTTP '+r.status)));
          renderTabServices();
        });
      };
    })(launches[l]);}
    var stops=$('view').querySelectorAll('button[data-stop]');
    for(var st=0;st<stops.length;st++){(function(btn){
      btn.onclick=function(){
        if(!confirm('остановить проект '+btn.dataset.stop+'?'))return;
        btn.disabled=true;btn.textContent='останавливаю...';
        api('/api/services/stop',{method:'POST',body:{group:btn.dataset.stop}}).then(function(r){
          if(r.status!==200)alert(((r.body&&r.body.error)||('HTTP '+r.status)));
          renderTabServices();
        });
      };
    })(stops[st]);}
    if($('madd'))$('madd').onclick=function(){
      var p=$('mport').value,s=$('msvc').value,u=$('mup').value;
      if(!p||!s)alert('нужны порт и сервис');else addService(p,s,u);
    };
    api('/api/services').then(function(r){
      var svc=(r.body.services)||[],routes=(r.body.routes)||[];
      setHTML($('aports'),svc.map(function(x){
        return '<div class="break"><span class="pill">:'+esc(x.port)+'</span> <b>'+esc(x.service)+'</b> <span class="muted">'+esc(x.upstream||'-')+'</span> <button class="act" data-rm="'+esc(x.port)+'">убрать</button></div>';
      }).join('')||'<div class="muted">нет</div>');
      setHTML($('aroutes'),'<div class="mut">роуты конфига (host)</div>'+routes.map(function(x){
        return '<div class="break">'+esc(x.host)+' → <b>'+esc(x.service)+'</b> <span class="muted">'+esc(x.upstream)+'</span> <button class="act" data-rmr="'+esc(x.host)+'">убрать</button></div>';
      }).join('')||'<div class="muted">нет</div>');
      var rms=$('view').querySelectorAll('button[data-rm]');
      for(var i2=0;i2<rms.length;i2++){
        rms[i2].onclick=function(){delService(Number(this.dataset.rm))};
      }
      var rmrs=$('view').querySelectorAll('button[data-rmr]');
      for(var i3=0;i3<rmrs.length;i3++){
        rmrs[i3].onclick=function(){
          api('/api/routes?host='+encodeURIComponent(this.dataset.rmr),{method:'DELETE'}).then(function(r){
            if(r.status!==200&&r.status!==404)alert(r.body.error||('HTTP '+r.status));renderTabServices();
          });
        };
      }
    });
  }
  function renderTabServices(){
    api('/api/discover',{method:'POST',body:{}}).then(function(r){renderServices(r.body)});
  }
  function loadAccounts(){
    api('/api/accounts').then(function(r){
      if(r.status!==200){viewErr(r);return;}
      var accs=(r.body&&r.body.accounts)||[];
      var out='<div class="card"><div class="mut">Новый аккаунт / изменить</div>'+
        '<div class="row2">'+
        '<input id="acl" placeholder="логин" size="14">'+
        '<input id="acp" type="password" placeholder="пароль (пусто = не менять)" size="24">'+
        '<select id="acr"><option value="team">team</option><option value="admin">admin</option></select>'+
        '<input id="acteam" placeholder="команда (для team)" size="14">'+
        '<button class="act" id="acsave">создать</button>'+
        '<button class="act" id="acnew">очистить</button></div>'+
        '<div class="muted" id="acerr"></div></div>';
      out+='<table>'+head(['логин','роль','команда',''])+
        (accs.length?accs.map(function(a){
          return '<tr><td><b>'+esc(a.login)+'</b></td><td>'+pill(a.role)+'</td>'+
            '<td>'+esc(a.team||'-')+'</td>'+
            '<td class="nowrap"><button class="act" data-edit="'+esc(a.login)+'">изменить</button> '+
            '<button class="act" data-del="'+esc(a.login)+'">удалить</button></td></tr>';
        }).join(''):'<tr><td colspan="4" class="muted">нет аккаунтов</td></tr>')+
        '</table>';
      out+='<div class="card" style="margin-top:12px"><div class="mut">Сменить свой пароль</div>'+
        '<div class="row2">'+
        '<input id="cwp" type="password" placeholder="текущий пароль" size="18">'+
        '<input id="cwn" type="password" placeholder="новый пароль" size="18">'+
        '<button class="act" id="cwgo">сменить</button><span class="muted" id="cwmsg"></span></div></div>';
      setView(out);
      function syncTeam(){var dis=$('acr').value!=='team';$('acteam').disabled=dis;if(dis)$('acteam').value='';}
      $('acr').onchange=syncTeam;syncTeam();
      $('acnew').onclick=function(){loadAccounts()};
      $('acsave').onclick=function(){
        $('acerr').textContent='';
        var login=($('acl').value||'').trim();
        if(!login){$('acerr').textContent='нужен логин';return;}
        var role=$('acr').value;
        var body={login:login,role:role};
        if($('acp').value)body.password=$('acp').value;
        if(role==='team')body.team=($('acteam').value||'').trim();
        var b=this;b.disabled=true;
        api('/api/accounts',{method:'POST',body:body}).then(function(rr){
          b.disabled=false;
          if(rr.status!==200){$('acerr').textContent=(rr.body&&rr.body.error)||('HTTP '+rr.status);return;}
          loadAccounts();
        });
      };
      var eb=document.querySelectorAll('#view [data-edit]');
      for(var i=0;i<eb.length;i++)eb[i].onclick=function(){
        var lg=this.dataset.edit;
        for(var k=0;k<accs.length;k++)if(accs[k].login===lg){
          $('acl').value=accs[k].login;$('acr').value=accs[k].role;$('acteam').value=accs[k].team||'';
          syncTeam();$('acp').value='';
          $('acsave').textContent='сохранить';
          $('acerr').textContent='пустой пароль = оставить прежний';
        }
      };
      var db=document.querySelectorAll('#view [data-del]');
      for(var j=0;j<db.length;j++)db[j].onclick=function(){
        var lg=this.dataset.del;
        if(!confirm('удалить аккаунт '+lg+'?'))return;
        api('/api/accounts?login='+encodeURIComponent(lg),{method:'DELETE'}).then(function(rr){
          if(rr.status!==200){alert((rr.body&&rr.body.error)||('HTTP '+rr.status));return;}
          loadAccounts();
        });
      };
      $('cwgo').onclick=function(){
        var b=this;b.disabled=true;
        api('/api/account/password',{method:'POST',body:{current:$('cwp').value,password:$('cwn').value}}).then(function(rr){
          b.disabled=false;
          $('cwmsg').textContent=rr.status===200?'пароль изменён':((rr.body&&rr.body.error)||('HTTP '+rr.status));
        });
      };
    });
  }
  function viewErr(r){
    $('view').innerHTML='<div class="bad">'+(r.body.error||('HTTP '+r.status))+'</div>';
    if(r.status===401||r.status===403)auth();
  }
  var selected=document.querySelectorAll('#nav button');
  for(var i=0;i<selected.length;i++){
    selected[i].onclick=function(){renderTab(this.dataset.tab)};
  }
  render();
  startAuto();
})();
</script>
</body>
</html>
`;