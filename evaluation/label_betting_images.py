"""
label_betting_images.py
-----------------------
Turn a folder of raw screenshots into a labelled evaluation set.

Step 1 of the betting workflow is collection, which needs a human. This tool
handles everything either side of it, so the only manual work left is looking
at each image and pressing one key.

Usage
-----
    # 1. Drop screenshots anywhere, then ingest them:
    python evaluation/label_betting_images.py ingest --src "C:/path/to/screenshots"

    # 2. Build an offline labelling page and open it in a browser:
    python evaluation/label_betting_images.py page

    # 3. Save the CSV the page gives you over manifest.csv, then:
    python evaluation/eval_betting_images.py

`ingest` is idempotent -- images are named by content hash, so re-running it
on the same folder will not create duplicates, and re-ingesting a screenshot
you already labelled will not lose its label.

Nothing here assigns a label on its own. A label that a script guessed is not
ground truth, and a test set seeded with the tool's own predictions measures
only whether the tool agrees with itself.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import os
import shutil
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET = BASE_DIR / "evaluation" / "datasets" / "betting_images"
STAGING = DATASET / "_unlabelled"
MANIFEST = DATASET / "manifest.csv"
PAGE = DATASET / "label.html"

IMAGE_EXT = {".png", ".jpg", ".jpeg", ".webp", ".bmp"}
FIELDS = ["filename", "is_betting", "source", "notes"]


# ---------------------------------------------------------------------------
def read_manifest() -> list[dict]:
    if not MANIFEST.exists():
        return []
    with open(MANIFEST, encoding="utf-8-sig", newline="") as f:
        return [r for r in csv.DictReader(f) if (r.get("filename") or "").strip()]


def labelled_hashes(rows: list[dict]) -> set[str]:
    """Content hashes already labelled, so ingest never re-stages them."""
    seen = set()
    for r in rows:
        stem = Path(r["filename"]).stem
        # staged files are named <hash8>_<original stem>
        seen.add(stem.split("_")[0])
    return seen


def sha8(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:8]


# ---------------------------------------------------------------------------
def cmd_ingest(src: str, source_tag: str) -> None:
    src_dir = Path(src)
    if not src_dir.is_dir():
        sys.exit("not a directory: %s" % src_dir)

    STAGING.mkdir(parents=True, exist_ok=True)
    rows = read_manifest()
    known = labelled_hashes(rows)
    staged_already = {p.name.split("_")[0] for p in STAGING.glob("*") if p.is_file()}

    found = [p for p in sorted(src_dir.rglob("*"))
             if p.is_file() and p.suffix.lower() in IMAGE_EXT]

    added, dupes = 0, 0
    for p in found:
        h = sha8(p)
        if h in known or h in staged_already:
            dupes += 1
            continue
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in p.stem)[:40]
        shutil.copy2(p, STAGING / ("%s_%s%s" % (h, safe, p.suffix.lower())))
        staged_already.add(h)
        added += 1

    print("scanned  : %d image(s) under %s" % (len(found), src_dir))
    print("staged   : %d new" % added)
    print("skipped  : %d (already staged or already labelled)" % dupes)
    print("staging  : %s" % STAGING)
    if added:
        print("\nnext: python evaluation/label_betting_images.py page")
    if source_tag:
        (STAGING / "_source.txt").write_text(source_tag, encoding="utf-8")


# ---------------------------------------------------------------------------
PAGE_TMPL = """<!doctype html>
<meta charset="utf-8">
<title>Label betting images</title>
<style>
  :root{color-scheme:light dark}
  body{font:15px/1.5 system-ui,sans-serif;margin:0;padding:24px;
       background:#0e1116;color:#e6edf3}
  h1{font-size:19px;margin:0 0 4px}
  p.sub{margin:0 0 18px;color:#9aa7b4}
  .bar{position:sticky;top:0;z-index:5;background:#0e1116;padding:12px 0;
       border-bottom:1px solid #263041;margin-bottom:18px}
  button{font:600 14px system-ui;padding:9px 16px;border-radius:7px;
         border:1px solid #2b3a52;background:#182338;color:#e6edf3;cursor:pointer}
  button:hover{background:#22314d}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:16px}
  .card{border:1px solid #263041;border-radius:9px;overflow:hidden;background:#131926}
  .card img{width:100%%;height:210px;object-fit:contain;background:#0a0d13;display:block}
  .card .fn{font-size:11px;color:#8b97a6;padding:6px 9px;word-break:break-all}
  .opts{display:flex;border-top:1px solid #263041}
  .opts label{flex:1;text-align:center;padding:9px 0;cursor:pointer;font-size:13px}
  .opts input{display:none}
  .opts label.bet{border-right:1px solid #263041}
  .opts input:checked+span{font-weight:700}
  .opts label.bet input:checked+span{color:#ff8080}
  .opts label.ben input:checked+span{color:#7ee787}
  .card.done{border-color:#3d5a80}
  textarea{width:100%%;height:190px;margin-top:18px;background:#0a0d13;color:#e6edf3;
           border:1px solid #263041;border-radius:7px;padding:11px;font:12px ui-monospace,monospace}
  code{background:#182338;padding:2px 6px;border-radius:4px}
</style>
<h1>Label betting images</h1>
<p class="sub">%(n)d unlabelled image(s). Mark each <b>Betting</b> or <b>Benign</b>,
then press Generate and save the CSV over
<code>evaluation/datasets/betting_images/manifest.csv</code>.</p>

<div class="bar">
  <button onclick="gen()">Generate manifest.csv</button>
  <button onclick="dl()">Download</button>
  <span id="count" style="margin-left:14px;color:#9aa7b4"></span>
</div>

<div class="grid">%(cards)s</div>
<textarea id="out" placeholder="manifest.csv appears here"></textarea>

<script>
const EXISTING = %(existing)s;
function upd(){
  const t=document.querySelectorAll('.card').length;
  let d=0;
  document.querySelectorAll('.card').forEach(c=>{
    const on=c.querySelector('input:checked');
    c.classList.toggle('done',!!on); if(on)d++;
  });
  document.getElementById('count').textContent=d+' / '+t+' labelled';
}
document.addEventListener('change',upd);
function esc(s){return /[",\\n]/.test(s)?'"'+s.replace(/"/g,'""')+'"':s}
function rows(){
  const out=[...EXISTING];
  document.querySelectorAll('.card').forEach(c=>{
    const on=c.querySelector('input:checked'); if(!on)return;
    out.push({filename:'_unlabelled/'+c.dataset.fn,is_betting:on.value,
              source:'collected',notes:''});
  });
  return out;
}
function csv(){
  const r=rows();
  return ['filename,is_betting,source,notes'].concat(
    r.map(x=>[x.filename,x.is_betting,x.source||'',x.notes||''].map(esc).join(','))
  ).join('\\n');
}
function gen(){document.getElementById('out').value=csv();upd()}
function dl(){
  const b=new Blob([csv()],{type:'text/csv'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(b);a.download='manifest.csv';a.click();
}
upd();
</script>
"""

CARD_TMPL = """
<div class="card" data-fn="%(fn)s">
  <img src="_unlabelled/%(fn)s" loading="lazy">
  <div class="fn">%(disp)s</div>
  <div class="opts">
    <label class="bet"><input type="radio" name="r%(i)d" value="1"><span>Betting</span></label>
    <label class="ben"><input type="radio" name="r%(i)d" value="0"><span>Benign</span></label>
  </div>
</div>"""


def cmd_page() -> None:
    if not STAGING.is_dir():
        sys.exit("nothing staged. Run: label_betting_images.py ingest --src <folder>")

    imgs = sorted(p for p in STAGING.iterdir()
                  if p.is_file() and p.suffix.lower() in IMAGE_EXT)
    if not imgs:
        sys.exit("no images in %s" % STAGING)

    cards = "".join(
        CARD_TMPL % {"fn": html.escape(p.name), "i": i,
                     "disp": html.escape(p.name[:52])}
        for i, p in enumerate(imgs))

    existing = read_manifest()
    import json
    PAGE.write_text(PAGE_TMPL % {
        "n": len(imgs),
        "cards": cards,
        "existing": json.dumps(existing),
    }, encoding="utf-8")

    print("wrote %s  (%d image(s) to label)" % (PAGE, len(imgs)))
    print("open it:  start %s" % PAGE)
    print("\nIt preserves the %d row(s) already in manifest.csv." % len(existing))


# ---------------------------------------------------------------------------
def cmd_status() -> None:
    rows = read_manifest()
    bet = sum(1 for r in rows if str(r.get("is_betting")).strip() == "1")
    ben = sum(1 for r in rows if str(r.get("is_betting")).strip() == "0")
    staged = len([p for p in STAGING.glob("*")
                  if p.is_file() and p.suffix.lower() in IMAGE_EXT]) if STAGING.is_dir() else 0

    print("manifest : %s" % MANIFEST)
    print("  betting: %3d   (target 150)" % bet)
    print("  benign : %3d   (target 150)" % ben)
    print("  staged, not yet labelled: %d" % staged)
    missing = [n for n, c in (("betting", bet), ("benign", ben)) if c < 150]
    if missing:
        print("\n  still short on: %s" % ", ".join(missing))
        print("  a set this small gives a smoke test, not a measurement.")
    else:
        print("\n  target met -- run: python evaluation/eval_betting_images.py")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_in = sub.add_parser("ingest", help="copy screenshots into the staging area")
    p_in.add_argument("--src", required=True, help="folder containing screenshots")
    p_in.add_argument("--source", default="", help="provenance tag, e.g. instagram_ad")

    sub.add_parser("page", help="build the offline labelling page")
    sub.add_parser("status", help="how far off the 150+150 target you are")

    a = ap.parse_args()
    if a.cmd == "ingest":
        cmd_ingest(a.src, a.source)
    elif a.cmd == "page":
        cmd_page()
    else:
        cmd_status()
