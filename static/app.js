// 一覧の絞り込みと、リンクのコピー。読み込めなくても記事は読める。
(function () {
  // このスクリプトの場所から、サイトの先頭までの相対パスを求める（階層の違うページで共通に使う）
  var self = document.currentScript && document.currentScript.getAttribute('src') || 'static/app.js';
  var pre = self.replace(/static\/app\.js.*$/, '');

  // 「自分の製品」: 登録した名前はこのブラウザの中（localStorage）にだけ置く
  var KEY = 'vw_watch';
  var getWatch = function () {
    try { var a = JSON.parse(localStorage.getItem(KEY) || '[]'); return Array.isArray(a) ? a : []; } catch (e) { return []; }
  };
  var setWatch = function (a) { try { localStorage.setItem(KEY, JSON.stringify(a)); } catch (e) {} };
  var norm = function (s) { return String(s).trim().toLowerCase().replace(/\s+/g, ' '); };
  // 名前が文中にあるか。短い英数字の名前（go、git など）は、単語として現れたときだけ一致とする
  var hasWord = function (text, kw) {
    var i = text.indexOf(kw);
    if (i < 0) return false;
    if (kw.length > 4 || !/^[a-z0-9]+$/.test(kw)) return true;
    var an = /[a-z0-9]/;
    while (i >= 0) {
      if (!an.test(i > 0 ? text.charAt(i - 1) : ' ') && !an.test(text.charAt(i + kw.length) || ' ')) return true;
      i = text.indexOf(kw, i + 1);
    }
    return false;
  };

  // 検索用の索引（search.json）。必要になったときに1回だけ読み込む
  var idx = null;
  var loadIdx = function (cb) {
    if (idx) return cb(idx);
    fetch(pre + 'search.json').then(function (r) { return r.json(); }).then(function (d) {
      idx = d.map(function (r) {
        return { id: r[0], title: r[1], prods: r[2], sum: r[3], score: r[5], sev: r[6], kev: r[7], upd: r[8],
                 head: (r[0] + ' ' + r[1] + ' ' + r[2]).toLowerCase(), body: (r[3] + ' ' + r[4]).toLowerCase() };
      });
      cb(idx);
    }).catch(function () { cb(null); });
  };
  var SEV = { critical: '緊急', high: '重要', medium: '警告', low: '注意' };
  var esc = function (s) {
    return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; });
  };
  var cardHtml = function (r) {
    var d = new Date(r.upd), day = isNaN(d) ? '' : d.toLocaleDateString('ja-JP', { timeZone: 'Asia/Tokyo' });
    return '<article class="card s-' + esc(r.sev) + '"><a class="card-link" href="' + pre + 'v/' + esc(r.id) + '.html">' +
      '<div class="meta"><span class="id">' + esc(r.id) + '</span><time>' + day + '</time></div>' +
      (r.prods ? '<p class="prod"><span>' + esc(r.prods) + '</span></p>' : '') +
      '<h2>' + esc(r.title) + '</h2><p class="lead">' + esc(r.sum) + '</p><div class="chips">' +
      (r.score != null ? '<span class="chip sev">' + (SEV[r.sev] || '') + ' <b>' + esc(r.score) + '</b></span>' : '<span class="chip">未評価</span>') +
      (r.kev ? '<span class="chip kev">悪用確認</span>' : '') + '</div></a></article>';
  };
  var newest = function (a, b) { return a.upd < b.upd ? 1 : a.upd > b.upd ? -1 : 0; };
  var mineHit = function (r, ws) { return ws.some(function (k) { return hasWord(r.head, k) || hasWord(r.body, k); }); };

  var list = document.getElementById('list');
  if (list) {
    var flag = '', q = document.getElementById('q'), empty = document.getElementById('empty');
    var mine = getWatch(), myb = document.querySelector('.filters button[data-f="my"]'), qall = document.getElementById('qall');
    if (myb && mine.length) myb.hidden = false;
    var apply = function () {
      var word = q ? q.value.trim().toLowerCase() : '', shown = 0;
      list.querySelectorAll('.card').forEach(function (c) {
        var hit = flag === 'my' ? mine.some(function (k) { return hasWord(c.dataset.text, k); })
                                : (' ' + c.dataset.flags + ' ').indexOf(' ' + flag + ' ') >= 0;
        var ok = (!flag || hit) &&
                 (!word || c.dataset.text.indexOf(word) >= 0);
        c.hidden = !ok;
        if (ok) shown++;
      });
      if (empty) empty.hidden = shown > 0;
    };
    document.querySelectorAll('.filters button').forEach(function (b) {
      b.addEventListener('click', function () {
        flag = b.dataset.f;
        document.querySelectorAll('.filters button').forEach(function (x) { x.classList.toggle('on', x === b); });
        apply();
      });
    });
    if (q) q.addEventListener('input', function () {
      apply();
      // 「サイト全体から探す」に、いま入れている言葉を引き継ぐ
      if (qall) qall.href = pre + 'search.html' + (q.value.trim() ? '?q=' + encodeURIComponent(q.value.trim()) : '');
    });
  }

  // 検索ページ: 言葉をすべて含む記事を出す。番号・見出し・製品名に当たった件を先に、その中は新しい順
  var sq = document.getElementById('sq'), res = document.getElementById('results'), sinfo = document.getElementById('sinfo');
  if (sq && res) {
    var search = function () {
      var words = norm(sq.value).split(' ').filter(Boolean);
      if (!words.length) { res.innerHTML = ''; sinfo.textContent = ''; return; }
      loadIdx(function (ix) {
        if (!ix) { sinfo.textContent = '検索用のデータを読み込めませんでした。時間をおいて、もう一度お試しください。'; return; }
        var hits = [];
        ix.forEach(function (r) {
          var tier = 0;
          for (var i = 0; i < words.length; i++) {
            if (r.head.indexOf(words[i]) >= 0) continue;
            if (r.body.indexOf(words[i]) < 0) return;
            tier = 1;
          }
          hits.push({ t: tier, r: r });
        });
        hits.sort(function (a, b) { return a.t - b.t || newest(a.r, b.r); });
        sinfo.textContent = hits.length ? hits.length + '件' + (hits.length > 100 ? '（上位100件を表示）' : '')
                                        : '条件に合う記事がありません。言葉を減らすか、英語の製品名でお試しください。';
        res.innerHTML = hits.slice(0, 100).map(function (h) { return cardHtml(h.r); }).join('');
      });
    };
    var qm = location.search.match(/[?&]q=([^&]*)/), timer1;
    if (qm) { try { sq.value = decodeURIComponent(qm[1].replace(/\+/g, ' ')); } catch (e) {} }
    sq.addEventListener('input', function () { clearTimeout(timer1); timer1 = setTimeout(search, 150); });
    search();
  }

  // 「自分の製品」ページ: 登録と解除、関係しそうな記事の一覧
  var wform = document.getElementById('wform');
  if (wform && res) {
    var winput = document.getElementById('winput'), wlist = document.getElementById('wlist'), winfo = document.getElementById('winfo');
    // 自分専用のRSSのURL。登録した名前と、選んだ絞り込みから作る
    var fbox = document.getElementById('myfeed'), furl = document.getElementById('feedurl');
    var feed = function () {
      if (!fbox || !furl) return;
      var ws = getWatch(), opt = fbox.querySelector('input[name="fmin"]:checked'), v = opt ? opt.value : '';
      fbox.hidden = !ws.length;
      furl.textContent = fbox.dataset.base + '/feed?watch=' + ws.map(encodeURIComponent).join(',') +
        (v === 'kev' ? '&only=kev' : v ? '&min=' + v : '');
    };
    if (fbox) fbox.querySelectorAll('input[name="fmin"]').forEach(function (o) { o.addEventListener('change', feed); });
    var draw = function () {
      var ws = getWatch();
      wlist.innerHTML = '';
      ws.forEach(function (k) {
        var b = document.createElement('button');
        b.type = 'button';
        b.className = 'tag';
        b.textContent = k + ' ×';
        b.setAttribute('aria-label', k + ' の登録を外す');
        b.addEventListener('click', function () { setWatch(getWatch().filter(function (x) { return x !== k; })); draw(); });
        wlist.appendChild(b);
      });
      feed();
      if (!ws.length) { res.innerHTML = ''; winfo.textContent = 'まだ登録がありません。上の欄に製品名を入れて登録してください。'; return; }
      loadIdx(function (ix) {
        if (!ix) { winfo.textContent = '記事のデータを読み込めませんでした。時間をおいて、もう一度お試しください。'; return; }
        var hits = ix.filter(function (r) { return mineHit(r, ws); }).sort(newest);
        winfo.textContent = hits.length ? '関係しそうな記事 ' + hits.length + '件' + (hits.length > 100 ? '（新しい100件を表示）' : '') + '。新しい順です。'
                                        : 'いま掲載中の記事に、関係しそうなものはありません。';
        res.innerHTML = hits.slice(0, 100).map(cardHtml).join('');
      });
    };
    wform.addEventListener('submit', function (e) {
      e.preventDefault();
      var k = norm(winput.value), ws = getWatch();
      if (k.length < 2) return;
      if (ws.indexOf(k) < 0 && ws.length < 30) { ws.push(k); setWatch(ws); }
      winput.value = '';
      draw();
    });
    draw();
  }

  // 製品ページの「自分の製品に登録する」ボタン
  document.querySelectorAll('button[data-watch]').forEach(function (b) {
    var k = norm(b.dataset.watch);
    var show = function () {
      var on = getWatch().indexOf(k) >= 0;
      b.classList.toggle('on', on);
      b.textContent = on ? '「自分の製品」に登録済み（押すと外す）' : '「自分の製品」に登録する';
    };
    b.addEventListener('click', function () {
      var ws = getWatch(), i = ws.indexOf(k);
      if (i >= 0) ws.splice(i, 1); else if (ws.length < 30) ws.push(k);
      setWatch(ws);
      show();
    });
    b.hidden = false;
    show();
  });

  // トップ: 登録がある人には、関係しそうな記事の件数を出す
  var mybar = document.getElementById('mybar');
  if (mybar && getWatch().length) loadIdx(function (ix) {
    if (!ix) return;
    var ws = getWatch(), since = new Date(Date.now() - 7 * 864e5).toISOString();
    var hits = ix.filter(function (r) { return mineHit(r, ws); });
    var recent = hits.filter(function (r) { return r.upd >= since; }).length;
    var a = document.createElement('a');
    a.href = pre + 'my.html';
    a.textContent = '一覧を見る';
    mybar.textContent = '自分の製品に関係しそうな記事: この7日間で ' + recent + '件（掲載中 ' + hits.length + '件）。';
    mybar.appendChild(a);
  });
  // トップのスライド: 5秒ごとに送る。触っている間と「動きを減らす」設定のときは止める。
  var track = document.getElementById('slides'), nav = document.getElementById('slides-nav');
  if (track && nav && track.children.length > 1) {
    var n = track.children.length, cur = 0, timer = null, dots = nav.querySelector('.dots');
    var calm = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var go = function (i) {
      cur = (i + n) % n;
      track.scrollTo({ left: cur * track.clientWidth, behavior: calm ? 'auto' : 'smooth' });
    };
    var mark = function () {
      cur = Math.round(track.scrollLeft / track.clientWidth);
      dots.querySelectorAll('button').forEach(function (b, i) { b.classList.toggle('on', i === cur); });
    };
    var start = function () { if (!calm && !timer) timer = setInterval(function () { go(cur + 1); }, 5000); };
    var stop = function () { clearInterval(timer); timer = null; };
    for (var i = 0; i < n; i++) (function (i) {
      var b = document.createElement('button');
      b.type = 'button';
      b.setAttribute('aria-label', (i + 1) + '枚目を表示');
      b.addEventListener('click', function () { go(i); });
      dots.appendChild(b);
    })(i);
    nav.querySelectorAll('button[data-d]').forEach(function (b) {
      b.addEventListener('click', function () { go(cur + Number(b.dataset.d)); });
    });
    var box = track.parentNode;
    ['pointerenter', 'focusin', 'touchstart'].forEach(function (e) { box.addEventListener(e, stop, { passive: true }); });
    ['pointerleave', 'focusout'].forEach(function (e) { box.addEventListener(e, start); });
    document.addEventListener('visibilitychange', function () { document.hidden ? stop() : start(); });
    track.addEventListener('scroll', mark, { passive: true });
    nav.hidden = false;
    mark();
    start();
  }
  var copy = document.getElementById('copy');
  if (copy) copy.addEventListener('click', function () {
    var done = function (t) { copy.textContent = t; setTimeout(function () { copy.textContent = 'リンクをコピー'; }, 1800); };
    try { navigator.clipboard.writeText(copy.dataset.url).then(function () { done('コピーしました'); }, function () { done('コピーできませんでした'); }); }
    catch (e) { done('コピーできませんでした'); }
  });
  // 404ページ: 記事のURLだったときは、そのCVEの一次情報（NVD）へ案内する
  var gone = document.getElementById('gone'), m = location.pathname.match(/\/v\/(CVE-\d{4}-\d+)/i);
  if (gone && m) {
    var id = m[1].toUpperCase(), a = document.createElement('a');
    a.href = 'https://nvd.nist.gov/vuln/detail/' + id;
    a.rel = 'noopener';
    a.textContent = 'NVDで ' + id + ' を見る';
    gone.textContent = id + ' の記事は、いまこのサイトにありません。';
    gone.appendChild(a);
    gone.hidden = false;
  }
  // 「AIで使う」ページの依頼文をコピーするボタン（data-copy に、写す要素の id）
  document.querySelectorAll('button[data-copy]').forEach(function (b) {
    var label = b.textContent;
    b.addEventListener('click', function () {
      var src = document.getElementById(b.dataset.copy);
      var done = function (t) { b.textContent = t; setTimeout(function () { b.textContent = label; }, 1800); };
      try { navigator.clipboard.writeText(src.textContent).then(function () { done('コピーしました'); }, function () { done('コピーできませんでした'); }); }
      catch (e) { done('コピーできませんでした'); }
    });
  });
})();
