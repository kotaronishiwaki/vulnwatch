// 自分専用のRSS（Cloudflare Pages Functions）
//
//   /feed?watch=nginx,fortigate            登録した名前に関係しそうな記事
//   /feed?watch=nginx&min=9                CVSS 9.0 以上だけ（悪用確認済みはスコアにかかわらず入れる）
//   /feed?watch=nginx&only=kev             悪用確認済みだけ
//
// 条件はURLに入っているだけで、こちらでは何も保存しない。
// 記事のデータは、サイト生成のときに作る feed-index.txt（pipeline/build.py の feed_index）を読む。
// 1行が1件、タブ区切りで、新しい順:
//   CVE番号, 更新日時, スコア, 深刻度の表示, 悪用確認(0/1), 見出し, 要約, 直近の追記, 照合用の文（小文字）
// 無料枠は1回の処理時間が短いので、JSONに直さず、文字列の検索だけで照合する。

const SITE = '脆弱性ウォッチ';
const MAX_ITEMS = 50;   // フィードに入れる件数
const MAX_WORDS = 20;   // 1つのURLで見る名前の数
const ALNUM = /[a-z0-9]/;

const xml = (s) => String(s)
  .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '')
  .replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c]));

export function parseWords(raw) {
  const seen = new Set();
  for (const w of String(raw || '').split(',')) {
    const k = w.trim().toLowerCase().replace(/\s+/g, ' ');
    if (k.length >= 2 && k.length <= 60 && !/[\t\n\r]/.test(k)) seen.add(k);
  }
  return [...seen].slice(0, MAX_WORDS);
}

// text から、名前のどれかに当たる行を新しい順に取り出す。返り値は項目の配列の配列。
export function pick(text, words, min, onlyKev) {
  const found = new Map();  // 行の先頭の位置 → 項目
  for (const w of words) {
    // 短い英数字の名前（go、git など）は、単語として現れたときだけ一致とする
    const short = w.length <= 4 && /^[a-z0-9]+$/.test(w);
    let n = 0;
    let i = text.indexOf(w);
    while (i >= 0 && n < MAX_ITEMS) {
      const ls = text.lastIndexOf('\n', i) + 1;
      let le = text.indexOf('\n', i);
      if (le < 0) le = text.length;
      const hs = text.lastIndexOf('\t', le - 1) + 1;  // 照合用の文（最後の項目）の先頭
      if (hs <= ls || i < hs) {  // 照合用の文より前（見出しなど）で当たった。照合用の文から探し直す
        i = text.indexOf(w, Math.max(i + 1, hs));
        continue;
      }
      const ok = !short || (!ALNUM.test(i > hs ? text[i - 1] : ' ') && !ALNUM.test(i + w.length < le ? text[i + w.length] : ' '));
      if (!ok) {
        i = text.indexOf(w, i + 1);
        continue;
      }
      if (!found.has(ls)) {
        const f = text.slice(ls, hs - 1).split('\t');
        const kev = f[4] === '1';
        const pass = f.length >= 8 && (!onlyKev || kev) && (kev || !min || parseFloat(f[2]) >= min);
        found.set(ls, pass ? f : null);
      }
      if (found.get(ls)) n++;
      i = text.indexOf(w, le);  // 次の行へ
    }
  }
  return [...found.entries()].filter((e) => e[1]).sort((a, b) => a[0] - b[0]).slice(0, MAX_ITEMS).map((e) => e[1]);
}

export function rss(origin, selfUrl, words, rows) {
  const items = rows.map(([id, upd, , label, kev, title, summary, update]) => {
    const head = (update ? '【追記】' : '') + (kev === '1' ? '【悪用確認】' : '') + title + '（' + id + '）';
    const desc = [label ? '深刻度 ' + label + '。' : '', summary, update ? ' 追記: ' + update : ''].join('');
    const d = new Date(upd);
    const pub = isNaN(d) ? '' : '<pubDate>' + d.toUTCString() + '</pubDate>';
    return '<item><title>' + xml(head) + '</title><link>' + origin + '/v/' + xml(id) + '</link>' +
      '<guid isPermaLink="false">' + xml(id + '-' + upd) + '</guid>' + pub +
      '<description>' + xml(desc) + '</description></item>';
  });
  const name = words.join('、');
  return '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel>' +
    '<title>' + xml(name + ' の脆弱性 | ' + SITE) + '</title><link>' + origin + '/my</link>' +
    '<description>' + xml('登録した名前（' + name + '）に関係しそうな脆弱性の新着と追記。名前の部分一致で選んでいるので、関係のない件が混ざることがあります。') + '</description>' +
    '<language>ja</language><atom:link href="' + xml(selfUrl) + '" rel="self" type="application/rss+xml"/>' +
    items.join('') + '</channel></rss>';
}

export async function onRequestGet({ request, env, waitUntil }) {
  const url = new URL(request.url);
  const words = parseWords(url.searchParams.get('watch'));
  if (!words.length) return Response.redirect(url.origin + '/my', 302);
  const min = Math.min(10, Math.max(0, parseFloat(url.searchParams.get('min')) || 0));
  const onlyKev = url.searchParams.get('only') === 'kev';

  // 同じ条件の取得は、15分のあいだ作り置きを返す（RSSリーダーは同じURLを何度も取りに来る）
  const key = new Request(url.origin + '/feed?watch=' + words.map(encodeURIComponent).join(',') + '&min=' + min + (onlyKev ? '&only=kev' : ''));
  let cache = null;
  try {
    cache = caches.default;
    const hit = await cache.match(key);
    if (hit) return hit;
  } catch (e) { cache = null; }

  const res = await env.ASSETS.fetch(new URL('/feed-index.txt', url));
  if (!res.ok) return new Response('feed data is unavailable', { status: 503, headers: { 'Retry-After': '600' } });
  const rows = pick(await res.text(), words, min, onlyKev);

  const out = new Response(rss(url.origin, url.toString(), words, rows), {
    headers: {
      'Content-Type': 'application/rss+xml; charset=utf-8',
      'Cache-Control': 'public, max-age=900',  // データの更新は1時間ごと
      'X-Robots-Tag': 'noindex',
    },
  });
  if (cache) {
    try { waitUntil(cache.put(key, out.clone())); } catch (e) { /* 作り置きできなくても、返すものは同じ */ }
  }
  return out;
}
