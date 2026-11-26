// 一覧の絞り込みと、リンクのコピー。読み込めなくても記事は読める。
(function () {
  var list = document.getElementById('list');
  if (list) {
    var flag = '', q = document.getElementById('q'), empty = document.getElementById('empty');
    var apply = function () {
      var word = q ? q.value.trim().toLowerCase() : '', shown = 0;
      list.querySelectorAll('.card').forEach(function (c) {
        var ok = (!flag || (' ' + c.dataset.flags + ' ').indexOf(' ' + flag + ' ') >= 0) &&
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
    if (q) q.addEventListener('input', apply);
  }
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
