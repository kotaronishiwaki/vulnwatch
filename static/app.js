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
  var copy = document.getElementById('copy');
  if (copy) copy.addEventListener('click', function () {
    var done = function (t) { copy.textContent = t; setTimeout(function () { copy.textContent = 'リンクをコピー'; }, 1800); };
    try { navigator.clipboard.writeText(copy.dataset.url).then(function () { done('コピーしました'); }, function () { done('コピーできませんでした'); }); }
    catch (e) { done('コピーできませんでした'); }
  });
})();
