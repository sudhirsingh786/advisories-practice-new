#!/usr/bin/env python3
"""Build the InfoSec advisory site from Word (.docx) and Markdown (.md) files.

Standard library only: nothing is downloaded at build time, and the output
pages contain no JavaScript, no external fonts, no CDN links and no API calls.

Usage:  python3 tools/build.py <advisories_dir> <output_dir>

One advisory per file, named after the CVE, for example
advisories/CVE-2026-114938.docx or advisories/CVE-2026-114938.md.
The CVE ID always comes from the file name.

The build never stops because of content. Anything missing or unusual gets a
safe default and a warning in the GitHub Actions log; a file that cannot be
read at all still gets a page saying so, and every other advisory is built.

Header values (Name, Severity, Stage, Published, Updated, Summary) are read,
in this order, from:
  1. a two-column table whose left column has those labels (Word template),
  2. "Label: value" lines near the top, or a --- header block (Markdown),
  3. defaults: Published = first Git commit of the file, Updated = last Git
     commit of the file, Name = title or first heading, Stage = Identify,
     Severity = Unknown, Summary = first paragraph.
Updated always uses the last Git commit date when Git history is available.

Word documents: no particular styles are required. A line is treated as a
heading when it uses a Word heading style or outline level, matches a known
section title (with or without numbering or emoji), looks like "# Title", or
is a short line in bold. Word bullets and numbering, typed bullets (-, *, •,
1., a)), tables (including merged cells), bold, italic, strikethrough,
monospace text, line breaks and hyperlinks are kept in document order.
Tracked deletions and comments are ignored; images are dropped.

All text is HTML-escaped, and only https:// and relative links are kept.
"""
import datetime
import difflib
import html
import pathlib
import re
import shutil
import subprocess
import sys
import zipfile
import xml.etree.ElementTree as ET

ALLOWED_LINK = re.compile(r"^(https://|\./|\.\./|#|[A-Za-z0-9_\-]+\.html)", re.I)
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
CSP = ("default-src 'none'; style-src 'self'; img-src 'self'; "
       "base-uri 'none'; form-action 'none'")
TEMPLATE_HINT = re.compile(r"^\s*(How to use:|Free section\.)", re.I)
STAGES = ["Identify", "Prioritize", "Remediate", "Monitor", "Closed"]
SEVERITIES = ["Critical", "High", "Medium", "Low"]
META_LABELS = {
    "id": ["cve id", "cve", "id", "cve number", "cve ids"],
    "name": ["name", "common name", "title", "vulnerability name", "vulnerability"],
    "severity": ["severity", "cvss severity", "vulnerability severity"],
    "status": ["stage", "status", "response stage", "current stage"],
    "published": ["published", "published date", "date published", "disclosure date",
                  "public disclosure", "disclosed"],
    "updated": ["updated", "last updated", "last update", "updated date", "date updated"],
    "summary": ["summary", "description", "short description", "overview", "one line summary"],
}
KNOWN_SECTIONS = ["what you need to do", "threat status", "why the cpu matters", "am i affected",
                  "affected and fixed versions", "how to fix", "frequently asked questions", "faq",
                  "links", "vulnerability details", "references", "timeline", "detection",
                  "mitigation", "remediation", "background", "technical details", "notes"]
MONO_FONTS = ("consolas", "courier", "courier new", "lucida console", "menlo", "monaco",
              "source code pro", "cascadia", "fira code", "dejavu sans mono", "monospace")

WARNINGS = []


def warn(path, message):
    """Record a warning; GitHub Actions shows ::warning lines as annotations."""
    WARNINGS.append("%s: %s" % (path, message))
    print("::warning file=%s::%s" % (path, message.replace("\n", " ")))


# ================================================================ helpers
def norm_label(text):
    t = re.sub(r"[^a-z0-9 ]+", " ", text.lower())
    return re.sub(r"\s+", " ", t).strip()


def meta_key(label):
    lab = norm_label(label)
    for key, names in META_LABELS.items():
        if lab in names:
            return key
    return None


def section_title(text):
    """Return the cleaned title if text looks like a known section heading."""
    t = re.sub(r"^[\W\d_]+", "", text.strip(), flags=re.UNICODE)  # numbering, emoji, bullets
    t = norm_label(t)
    for s in KNOWN_SECTIONS:
        if t == s or (t.startswith(s) and len(t) <= len(s) + 25):
            return True
    return False


def norm_date(value):
    v = (value or "").strip().strip("\"'")
    if not v or v in ("-", "YYYY-MM-DD"):
        return ""
    v = re.sub(r"(\d)(st|nd|rd|th)\b", r"\1", v)
    candidates = [v, v.replace(",", ""), re.sub(r"\s+", " ", v.replace(",", " "))]
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%d/%m/%Y", "%d.%m.%Y", "%d %b %Y",
                "%d %B %Y", "%b %d %Y", "%B %d %Y", "%d-%b-%Y", "%d-%B-%Y",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"):
        for c in candidates:
            try:
                return datetime.datetime.strptime(c.strip(), fmt).strftime("%Y-%m-%d")
            except ValueError:
                continue
    m = re.search(r"\d{4}-\d{2}-\d{2}", v)
    return m.group(0) if m else v


def norm_choice(value, choices, default):
    v = (value or "").strip().strip("\"'")
    low = v.lower().replace("prioritise", "prioritize")
    for c in choices:
        if c.lower() in low:
            return c
    return v or default


SEVERITY_WORDS = {"critical": "Critical", "crit": "Critical", "high": "High", "important": "High",
                  "medium": "Medium", "med": "Medium", "moderate": "Medium", "low": "Low"}
STAGE_WORDS = {"identify": "Identify", "identification": "Identify", "identified": "Identify",
               "prioritize": "Prioritize", "prioritise": "Prioritize", "prioritization": "Prioritize",
               "prioritisation": "Prioritize", "priority": "Prioritize", "triage": "Prioritize",
               "remediate": "Remediate", "remediation": "Remediate", "remediating": "Remediate",
               "fix": "Remediate", "fixing": "Remediate", "patching": "Remediate",
               "monitor": "Monitor", "monitoring": "Monitor", "verify": "Monitor", "verification": "Monitor",
               "closed": "Closed", "close": "Closed", "done": "Closed", "resolved": "Closed", "complete": "Closed",
               "completed": "Closed"}


def is_placeholder(value):
    """Untouched template text such as <Critical / High / Medium / Low>."""
    v = (value or "").strip()
    return (v.startswith("<") and v.endswith(">")) or v.count("/") >= 2


def fuzzy_pick(value, words):
    """Map free text to a known value: exact word, then close spelling. Returns (value, guessed)."""
    if is_placeholder(value):
        return "", False
    tokens = re.findall(r"[a-z]+", (value or "").lower())
    for tok in tokens:
        if tok in words:
            return words[tok], False
    for tok in tokens:
        if len(tok) >= 3:
            close = difflib.get_close_matches(tok, list(words), n=1, cutoff=0.75)
            if close:
                return words[close[0]], True
    return "", False


def norm_severity(value):
    """Critical/High/Medium/Low from words, typos (Crickal) or a CVSS score (9.8). Returns (value, guessed)."""
    sev, guessed = fuzzy_pick(value, SEVERITY_WORDS)
    if sev:
        return sev, guessed
    scores = [float(x) for x in re.findall(r"(?<![\w.])(10(?:\.0)?|\d(?:\.\d)?)(?![\d.])", value or "")]
    if scores:
        n = max(scores)  # "CVSS 3.1 7.5" -> 7.5
        band = "Critical" if n >= 9 else "High" if n >= 7 else "Medium" if n >= 4 else "Low" if n > 0 else ""
        if band:
            return band, True
    return "", False


def git_dates(path):
    """(first commit date, last commit date) of a file, or ("", "") without Git history."""
    try:
        out = subprocess.run(["git", "log", "--follow", "--format=%cs", "--", str(path)],
                             capture_output=True, text=True, timeout=20, cwd=str(path.parent))
        dates = [d for d in out.stdout.split() if re.fullmatch(r"\d{4}-\d{2}-\d{2}", d)]
        if out.returncode == 0 and dates:
            return dates[-1], dates[0]
    except (OSError, subprocess.SubprocessError):
        pass
    return "", ""


def finish_meta(meta, path, first_text=""):
    """Fill every field with a usable value; warn about what was guessed."""
    found = CVE_ID.search(path.stem)
    file_id = found.group(0).upper() if found else path.stem
    if not found:
        warn(path, "file name should be the CVE ID, for example CVE-2026-12345.docx")
    if meta.get("id") and CVE_ID.search(meta["id"]) and \
            CVE_ID.search(meta["id"]).group(0).upper() != file_id:
        warn(path, "CVE ID inside the file (%s) differs from the file name; using %s"
             % (meta["id"], file_id))
    meta["id"] = file_id

    meta["name"] = (meta.get("name") or "").strip().strip("\"'")
    meta["name"] = re.sub(r"^\s*%s\s*[-:–—]*\s*" % re.escape(file_id), "", meta["name"], flags=re.I)
    if not meta["name"] or "<" in meta["name"]:
        meta["name"] = meta.get("_title") or file_id
        warn(path, "no name given; showing '%s'" % meta["name"])

    raw_sev = (meta.get("severity") or "").strip()
    sev, guessed = norm_severity(raw_sev)
    if not sev:
        warn(path, "severity '%s' not recognised; showing 'Unknown'" % raw_sev)
        sev = "Unknown"
    elif guessed:
        warn(path, "severity '%s' read as '%s'" % (raw_sev, sev))
    meta["severity"] = sev

    raw_st = (meta.get("status") or "").strip()
    st, guessed = fuzzy_pick(raw_st, STAGE_WORDS)
    if not st:
        if raw_st:
            warn(path, "stage '%s' not recognised; showing 'Identify'" % raw_st)
        st = "Identify"
    elif guessed:
        warn(path, "stage '%s' read as '%s'" % (raw_st, st))
    meta["status"] = st

    first, last = git_dates(path)
    pub = norm_date(meta.get("published"))
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", pub or ""):
        pub = first or pub or "-"
    meta["published"] = pub
    upd = last or norm_date(meta.get("updated")) or pub
    meta["updated"] = upd or "-"

    summ = (meta.get("summary") or "").strip().strip("\"'")
    if not summ or (summ.startswith("<") and summ.endswith(">")) or "One or two sentences" in summ:
        summ = first_text[:400]
        if not summ:
            warn(path, "no summary given")
    meta["summary"] = summ
    return meta


# ================================================================ inline Markdown
def inline(text):
    """Escape text, then apply code, bold, italic, strikethrough and safe links."""
    out = []
    for part in re.split(r"(`[^`]+`)", text):
        if len(part) > 1 and part.startswith("`") and part.endswith("`"):
            out.append("<code>%s</code>" % html.escape(part[1:-1], quote=True))
            continue
        seg = html.escape(part, quote=True)
        seg = re.sub(r"&lt;br\s*/?&gt;", "<br>", seg, flags=re.I)   # Copilot tables use <br>
        seg = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", seg)          # images: alt text only
        seg = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", seg)
        seg = re.sub(r"(?<!\w)__(.+?)__(?!\w)", r"<strong>\1</strong>", seg)
        seg = re.sub(r"~~(.+?)~~", r"<del>\1</del>", seg)
        seg = re.sub(r"(?<![*\w])\*([^*\s][^*]*?)\*(?![*\w])", r"<em>\1</em>", seg)
        seg = re.sub(r"(?<![_\w])_([^_\s][^_]*?)_(?![_\w])", r"<em>\1</em>", seg)

        def link(m):
            label, url = m.group(1), html.unescape(m.group(2))
            return '<a href="%s">%s</a>' % (html.escape(url, quote=True), label) \
                if ALLOWED_LINK.match(url) else label

        out.append(re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", link, seg))
    return "".join(out)


def render_list(items):
    """items: (level, ordered, html). Builds properly nested <ul>/<ol>."""
    out, stack = [], []
    for level, ordered, body in items:
        tag = "ol" if ordered else "ul"
        while stack and level < stack[-1][0]:
            out.append("</li></%s>" % stack.pop()[1])
        if stack and level == stack[-1][0] and tag != stack[-1][1]:
            out.append("</li></%s>" % stack.pop()[1])
        if not stack or level > stack[-1][0]:
            out.append("<%s><li>" % tag)
            stack.append((level, tag))
        else:
            out.append("</li><li>")
        out.append(body)
    while stack:
        out.append("</li></%s>" % stack.pop()[1])
    return "".join(out)


def heading_html(level, text_html, plain):
    level = max(2, min(level + 1, 6))  # page title is h1
    anchor = re.sub(r"[^a-z0-9]+", "-", plain.lower()).strip("-")[:60]
    return '<h%d id="%s">%s</h%d>' % (level, anchor, text_html, level)


# ================================================================ Markdown files
LIST_ITEM = re.compile(r"^(\s*)([-*+•▪◦·]|\d+[.)]|[a-zA-Z][.)])\s+(.*)$")
HR = re.compile(r"^\s{0,3}([-*_])(\s*\1){2,}\s*$")
FENCE = re.compile(r"^\s*(```+|~~~+)")


def indent_width(s):
    s = s.expandtabs(4)
    return len(s) - len(s.lstrip(" "))


def md_table(rows):
    def split_row(line):
        s = line.strip()
        s = s[1:] if s.startswith("|") else s
        s = s[:-1] if s.endswith("|") and not s.endswith("\\|") else s
        return [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", s)]

    parsed = [split_row(r) for r in rows]
    is_sep = lambda cells: any(cells) and all(re.fullmatch(r":?-+:?", c) for c in cells if c)
    header = parsed[0] if len(parsed) > 1 and is_sep(parsed[1]) else None
    body = [r for r in (parsed[2:] if header else parsed) if not is_sep(r)]
    if not body and not header:
        return ""
    width = max([len(r) for r in body] + ([len(header)] if header else [1]))
    pad = lambda r: r + [""] * (width - len(r))
    out = ['<div class="table"><table>']
    if header:
        out.append("<thead><tr>%s</tr></thead>" % "".join("<th>%s</th>" % inline(c) for c in pad(header)))
    out.append("<tbody>%s</tbody></table></div>" % "".join(
        "<tr>%s</tr>" % "".join("<td>%s</td>" % inline(c) for c in pad(r)) for r in body))
    return "".join(out)


def md_to_html(body):
    lines = body.split("\n")
    out, para, i = [], [], 0

    def flush():
        if para:
            parts = []
            for n, raw in enumerate(para):
                hard = raw.endswith("  ") or raw.rstrip().endswith("\\")
                piece = raw.strip().rstrip("\\").rstrip()
                parts.append(inline(piece) + ("<br>" if hard and n < len(para) - 1 else " "))
            out.append("<p>%s</p>" % "".join(parts).strip())
            para.clear()

    while i < len(lines):
        line, s = lines[i], lines[i].strip()
        fence = FENCE.match(line)
        if fence:
            flush()
            mark, code = fence.group(1)[:3], []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith(mark):
                code.append(lines[i])
                i += 1
            out.append("<pre><code>%s</code></pre>" % html.escape("\n".join(code)))
            i += 1
            continue
        if not s:
            flush()
            i += 1
            continue
        m = re.match(r"^(#{1,6})\s*(.*?)\s*#*\s*$", s)
        if m and m.group(2):
            flush()
            out.append(heading_html(len(m.group(1)), inline(m.group(2)), m.group(2)))
            i += 1
            continue
        if HR.match(line) and not LIST_ITEM.match(line):
            flush()
            out.append("<hr>")
            i += 1
            continue
        if s.startswith("|"):
            flush()
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(lines[i])
                i += 1
            out.append(md_table(rows))
            continue
        if s.startswith(">"):
            flush()
            quote = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                quote.append(re.sub(r"^\s*>\s?", "", lines[i]))
                i += 1
            out.append("<blockquote>%s</blockquote>" % md_to_html("\n".join(quote)))
            continue
        if LIST_ITEM.match(line):
            flush()
            items = []
            while i < len(lines):
                lm = LIST_ITEM.match(lines[i])
                if lm:
                    items.append([indent_width(lm.group(1)) // 2,
                                  lm.group(2)[0].isalnum(), lm.group(3).strip()])
                    i += 1
                elif lines[i].strip() and indent_width(lines[i]) > 0 and items \
                        and not lines[i].strip().startswith("|"):
                    items[-1][2] += " " + lines[i].strip()
                    i += 1
                else:
                    break
            out.append(render_list([(lv, o, inline(t)) for lv, o, t in items]))
            continue
        para.append(line)
        i += 1
    flush()
    return "\n".join(out)


def read_markdown(path):
    text = path.read_text(encoding="utf-8", errors="replace").lstrip("﻿")
    text = text.replace("\r\n", "\n").replace("\r", "\n").strip("\n")
    # Copilot often wraps the whole answer in ```markdown ... ```
    m = re.match(r"^\s*(```+|~~~+)\s*(markdown|md)?\s*\n(.*)\n\s*\1\s*$", text, re.S | re.I)
    if m:
        text = m.group(3)
        warn(path, "removed a code block wrapped around the whole file")
    meta, body = {}, text
    lines = text.split("\n")
    if lines and lines[0].strip() == "---":
        end = next((n for n in range(1, len(lines)) if lines[n].strip() == "---"), None)
        if end is None:
            warn(path, "header block has no closing --- line; reading it as body text")
        else:
            for line in lines[1:end]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    key = meta_key(k) or k.strip().lower()
                    meta[key] = v.strip().strip("\"'")
            body = "\n".join(lines[end + 1:])
    else:
        # "Label: value" or "**Label:** value" lines at the top
        keep = []
        for n, line in enumerate(lines):
            lm = re.match(r"^\s*[-*]?\s*\**([A-Za-z ]{2,25}?)\**\s*:\s*\**\s*(.+?)\s*$", line)
            key = meta_key(lm.group(1)) if lm else None
            if key and key not in meta and n < 25:
                meta[key] = lm.group(2).strip("* ")
            else:
                keep.append(line)
        body = "\n".join(keep)
        if not meta:
            warn(path, "no header block found; using defaults")
    title = re.search(r"^#{1,6}\s+(.+)$", body, re.M)
    meta["_title"] = re.sub(r"[#*_`]", "", title.group(1)).strip() if title else ""
    body_html = md_to_html(body)
    m = re.search(r"<p>(.*?)</p>", body_html, re.S)
    first = html.unescape(re.sub(r"<[^>]+>", "", m.group(1))).strip() if m else ""
    return meta, body_html, first


# ================================================================ Word files
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
PR = "{http://schemas.openxmlformats.org/package/2006/relationships}"


def wattr(el, name):
    return el.get(W + name) if el is not None else None


def on(el):
    """True if a toggle property such as <w:b/> is switched on."""
    return el is not None and (wattr(el, "val") or "true").lower() not in ("0", "false", "off", "none")


class Docx:
    def __init__(self, path):
        self.z = zipfile.ZipFile(path)
        names = set(self.z.namelist())
        doc_name = "word/document.xml"
        if doc_name not in names:
            doc_name = next((n for n in names if n.endswith("document.xml")), None)
            if not doc_name:
                raise ValueError("not a Word document (word/document.xml missing)")
        self.root = ET.fromstring(self.z.read(doc_name))
        self.styles, self.style_bold = self._styles(names)
        self.numfmt = self._numbering(names)
        self.links = self._rels(names)

    def _xml(self, names, name):
        return ET.fromstring(self.z.read(name)) if name in names else None

    def _styles(self, names):
        styles, bold = {}, set()
        root = self._xml(names, "word/styles.xml")
        if root is None:
            return styles, bold
        for st in root.iter(W + "style"):
            sid = wattr(st, "styleId") or ""
            nm = st.find(W + "name")
            styles[sid] = (wattr(nm, "val") or sid).lower()
            rpr = st.find(W + "rPr")
            if rpr is not None and on(rpr.find(W + "b")):
                bold.add(sid)
            ppr = st.find(W + "pPr")
            lvl = ppr.find(W + "outlineLvl") if ppr is not None else None
            if lvl is not None and not re.search(r"heading", styles[sid]):
                styles[sid] = "heading %d" % (int(wattr(lvl, "val") or 0) + 1)
        return styles, bold

    def _numbering(self, names):
        fmt = {}
        root = self._xml(names, "word/numbering.xml")
        if root is None:
            return fmt
        abstract = {}
        for an in root.iter(W + "abstractNum"):
            levels = {}
            for lvl in an.iter(W + "lvl"):
                f = lvl.find(W + "numFmt")
                levels[int(wattr(lvl, "ilvl") or 0)] = (wattr(f, "val") or "decimal")
            abstract[wattr(an, "abstractNumId")] = levels
        for num in root.iter(W + "num"):
            a = num.find(W + "abstractNumId")
            fmt[wattr(num, "numId")] = abstract.get(wattr(a, "val"), {})
        return fmt

    def _rels(self, names):
        links = {}
        root = self._xml(names, "word/_rels/document.xml.rels")
        if root is not None:
            for rel in root.iter(PR + "Relationship"):
                links[rel.get("Id")] = rel.get("Target", "")
        return links

    # ------------------------------------------------------------ runs
    def runs(self, el, fmt=None, link=None, out=None):
        """Collect (text, bold, italic, strike, mono, link) pieces in document order."""
        out = [] if out is None else out
        for child in el:
            tag = child.tag
            if tag in (W + "del", W + "moveFrom", W + "commentReference", W + "pPr",
                       W + "proofErr", W + "bookmarkStart", W + "bookmarkEnd"):
                continue
            if tag == W + "hyperlink":
                rid = child.get(R + "id")
                url = self.links.get(rid, "") if rid else ("#" + (wattr(child, "anchor") or ""))
                self.runs(child, fmt, url, out)
            elif tag == W + "r":
                rpr = child.find(W + "rPr")
                f = dict(fmt or {})
                if rpr is not None:
                    sty = rpr.find(W + "rStyle")
                    if sty is not None and wattr(sty, "val") in self.style_bold:
                        f["b"] = True
                    for k, name in (("b", "b"), ("i", "i"), ("s", "strike")):
                        el2 = rpr.find(W + name)
                        if el2 is not None:
                            f[k] = on(el2)
                    fonts = rpr.find(W + "rFonts")
                    if fonts is not None:
                        names = " ".join(filter(None, [wattr(fonts, "ascii"), wattr(fonts, "hAnsi")])).lower()
                        f["m"] = any(m in names for m in MONO_FONTS)
                for node in child:
                    t = node.tag
                    if t in (W + "t", W + "instrText") and t == W + "t":
                        out.append((node.text or "", f, link))
                    elif t == W + "tab":
                        out.append(("\t", f, link))
                    elif t in (W + "br", W + "cr"):
                        if wattr(node, "type") != "page":
                            out.append(("\n", f, link))
                    elif t == W + "noBreakHyphen":
                        out.append(("-", f, link))
                    elif t == W + "sym":
                        out.append(("", f, link))
                    elif t in (W + "drawing", W + "pict", W + "object"):
                        for tb in node.iter(W + "txbxContent"):  # text boxes: keep the text
                            for p in tb.iter(W + "p"):
                                out.append(("\n", f, link))
                                self.runs(p, f, link, out)
            elif tag in (W + "ins", W + "moveTo", W + "smartTag", W + "fldSimple",
                         W + "customXml", W + "sdt", W + "sdtContent", W + "dir", W + "bdo"):
                self.runs(child, fmt, link, out)
        return out

    @staticmethod
    def runs_to_html(pieces):
        out = []
        for text, f, link in pieces:
            if not text:
                continue
            h = html.escape(text).replace("\t", " ").replace("\n", "<br>")
            if f.get("m"):
                h = "<code>%s</code>" % h
            if f.get("s"):
                h = "<del>%s</del>" % h
            if f.get("i"):
                h = "<em>%s</em>" % h
            if f.get("b"):
                h = "<strong>%s</strong>" % h
            if link:
                h = '<a href="%s">%s</a>' % (html.escape(link, quote=True), h) \
                    if ALLOWED_LINK.match(link) else h
            out.append(h)
        res = "".join(out)
        for tag in ("strong", "em", "del", "code"):  # merge neighbouring identical tags
            res = res.replace("</%s><%s>" % (tag, tag), "")
        return res.strip().replace("<br><br><br>", "<br><br>")

    # ------------------------------------------------------------ paragraphs
    def para_info(self, p):
        ppr = p.find(W + "pPr")
        style, level, ordered, numbered = "", None, False, False
        if ppr is not None:
            ps = ppr.find(W + "pStyle")
            style = self.styles.get(wattr(ps, "val") or "", (wattr(ps, "val") or "").lower())
            numpr = ppr.find(W + "numPr")
            if numpr is not None:
                nid = wattr(numpr.find(W + "numId"), "val")
                if nid and nid != "0":
                    numbered = True
                    level = int(wattr(numpr.find(W + "ilvl"), "val") or 0)
                    ordered = self.numfmt.get(nid, {}).get(level, "decimal") not in ("bullet", "none")
            ol = ppr.find(W + "outlineLvl")
            if ol is not None and not numbered:
                style = style or "heading %d" % (int(wattr(ol, "val") or 0) + 1)
        if not numbered and re.search(r"list (bullet|number|paragraph)", style):
            numbered, level = True, 0
            ordered = "number" in style
        pieces = self.runs(p)
        text = "".join(t for t, _, _ in pieces).strip()
        return style, numbered, level or 0, ordered, pieces, text

    def heading_level(self, style, pieces, text):
        if not text:
            return None
        m = re.search(r"heading\s*(\d)", style)
        if m:
            return int(m.group(1))
        if style in ("title",):
            return 0
        if style == "subtitle":
            return 2
        if re.match(r"^#{1,6}\s+\S", text):
            return len(text) - len(text.lstrip("#"))
        if len(text) <= 90 and not text.endswith((".", ",", ";")):
            if section_title(text):
                return 1
            visible = [(t, f) for t, f, _ in pieces if t.strip()]
            if visible and all(f.get("b") for _, f in visible) and len(text.split()) <= 12:
                return 2
        return None

    # ------------------------------------------------------------ tables
    def table_rows(self, tbl):
        rows = []
        for tr in tbl.findall(W + "tr"):
            cells = []
            for tc in tr.findall(W + "tc"):
                tcpr = tc.find(W + "tcPr")
                span = int(wattr(tcpr.find(W + "gridSpan"), "val") or 1) if tcpr is not None and \
                    tcpr.find(W + "gridSpan") is not None else 1
                vm = tcpr.find(W + "vMerge") if tcpr is not None else None
                cont = vm is not None and (wattr(vm, "val") or "continue") == "continue"
                cells.append((tc, span, cont))
            hdr = tr.find(W + "trPr")
            is_hdr = hdr is not None and hdr.find(W + "tblHeader") is not None
            rows.append((cells, is_hdr))
        return rows

    def cell_text(self, tc):
        return " ".join(self.para_info(p)[5] for p in tc.findall(W + "p")).strip()

    def table_html(self, tbl):
        rows = self.table_rows(tbl)
        if not rows:
            return ""
        first_cells = rows[0][0]
        first_bold = any(self.cell_text(tc) for tc, _, _ in first_cells) and all(
            f.get("b") for tc, _, _ in first_cells for p in tc.findall(W + "p")
            for t, f, _ in self.runs(p) if t.strip())
        header_rows = 1 if (rows[0][1] or first_bold or len(rows) > 1) else 0

        def row_html(cells, tagname):
            out = []
            for tc, span, cont in cells:
                inner = "" if cont else self.blocks_html(list(tc), in_cell=True)
                out.append("<%s%s>%s</%s>" % (tagname, ' colspan="%d"' % span if span > 1 else "",
                                              inner, tagname))
            return "<tr>%s</tr>" % "".join(out)

        head = "".join(row_html(c, "th") for c, _ in rows[:header_rows])
        body = "".join(row_html(c, "td") for c, _ in rows[header_rows:])
        return '<div class="table"><table>%s%s</table></div>' % (
            "<thead>%s</thead>" % head if head else "", "<tbody>%s</tbody>" % body if body else "")

    def meta_table(self, tbl):
        """If the table is a Field/Value header table, return its values."""
        meta, hits = {}, 0
        for cells, _ in self.table_rows(tbl):
            texts = [self.cell_text(tc) for tc, _, cont in cells if not cont]
            if len(texts) >= 2:
                key = meta_key(texts[0])
                if key:
                    hits += 1
                    meta[key] = " ".join(t for t in texts[1:] if t).strip()
        return meta if hits >= 3 else None

    # ------------------------------------------------------------ body
    def blocks_html(self, elements, in_cell=False):
        out, items = [], []

        def flush_list():
            if items:
                out.append(render_list(items))
                items.clear()

        flat = []
        for el in elements:  # unwrap content controls and custom XML
            if el.tag in (W + "sdt",):
                content = el.find(W + "sdtContent")
                flat.extend(list(content) if content is not None else [])
            elif el.tag == W + "customXml":
                flat.extend(list(el))
            else:
                flat.append(el)
        for el in flat:
            if el.tag == W + "tbl":
                flush_list()
                out.append(self.table_html(el))
            elif el.tag == W + "p":
                style, numbered, level, ordered, pieces, text = self.para_info(el)
                if not text:
                    flush_list()
                    continue
                body = self.runs_to_html(pieces)
                raw = "".join(t for t, _, _ in pieces).replace("\t", "    ")
                typed = re.match(r"^(\s*)([-*•▪◦·–]|\d{1,2}[.)]|[a-z][.)])\s+", raw)
                lvl = None if in_cell else self.heading_level(style, pieces, text)
                is_heading = lvl is not None and lvl >= 1 and (
                    (not numbered and not typed) or re.search(r"heading", style)
                    or ((ordered or (typed and typed.group(2)[0].isdigit())) and section_title(text)))
                if not is_heading and numbered:
                    items.append((level, ordered, body))
                    continue
                if not is_heading and typed:
                    body = self.runs_to_html(self.strip_prefix(
                        [(x.replace("\t", "    "), f, l) for x, f, l in pieces], len(typed.group(0))))
                    items.append((len(typed.group(1)) // 2, typed.group(2)[0].isalnum(), body))
                    continue
                flush_list()
                if is_heading:
                    plain = re.sub(r"^#+\s*", "", text)
                    out.append(heading_html(lvl, html.escape(plain) if text.startswith("#")
                                            else re.sub(r"</?strong>", "", body), plain))
                elif lvl == 0:
                    continue  # Title line becomes the page title
                elif re.search(r"quote", style):
                    out.append("<blockquote><p>%s</p></blockquote>" % body)
                elif in_cell:
                    out.append(body + "<br>")
                else:
                    out.append("<p>%s</p>" % body)
        flush_list()
        res = "".join(out)
        return res[:-4] if in_cell and res.endswith("<br>") else res

    @staticmethod
    def strip_prefix(pieces, n):
        out = []
        for text, f, link in pieces:
            if n > 0:
                cut = min(n, len(text))
                text, n = text[cut:], n - cut
            out.append((text, f, link))
        return out

    def read(self, path):
        body = self.root.find(W + "body")
        elements = list(body) if body is not None else []
        meta, title = {}, ""
        content, before_heading = [], True
        meta_done, first_heading = False, ""
        for el in elements:
            if el.tag == W + "tbl" and not meta_done:
                found = self.meta_table(el)
                if found:
                    meta.update({k: v for k, v in found.items() if v})
                    meta_done = True
                    continue
            if el.tag == W + "p":
                style, numbered, _, _, pieces, text = self.para_info(el)
                if TEMPLATE_HINT.match(text or ""):
                    continue  # grey "How to use" / "Free section" hints from the template
                if not title and text and (style == "title" or (
                        re.search(r"heading\s*1", style) and CVE_ID.search(text))):
                    title = text
                    continue
                if before_heading and text and not numbered:
                    lm = re.match(r"^\s*([A-Za-z ]{2,25}?)\s*[:\-–]\s*(.+)$", text)
                    key = meta_key(lm.group(1)) if lm else None
                    if key and key not in meta:
                        meta[key] = lm.group(2).strip()
                        continue
                lvl = self.heading_level(style, pieces, text)
                if lvl and (re.search(r"heading", style) or section_title(text)):
                    before_heading = False  # header lines are read until the first real section
                elif lvl and not first_heading and before_heading and not meta.get("name"):
                    first_heading = re.sub(r"^#+\s*", "", text)
                    continue  # this line becomes the page title
            content.append(el)
        if title and "name" not in meta:
            meta["name"] = re.sub(r"^\s*CVE-\d{4}-\d{4,7}\s*[-:–—]*\s*", "", title, flags=re.I)
        meta["_title"] = meta.get("name", "") or first_heading
        first = ""
        for el in content:
            if el.tag == W + "p":
                style, numbered, _, _, pieces, text = self.para_info(el)
                if text and not numbered and self.heading_level(style, pieces, text) is None:
                    first = text
                    break
        return meta, self.blocks_html(content), first


def read_docx(path):
    doc = Docx(path)
    return doc.read(path)


# ================================================================ page shell
def page(title, content, depth):
    css = "../" * depth + "assets/style.css"
    home = "../" * depth + "index.html"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<title>{html.escape(title)}</title>
<link rel="stylesheet" href="{css}">
</head>
<body>
<header><a class="brand" href="{home}">InfoSec Security Advisories</a>
<span class="tag">Internal</span></header>
<main>
{content}
</main>
<footer>Owned by InfoSec. Questions: security@company.com. Classification: Internal.</footer>
</body>
</html>
"""


def badge(kind, value):
    cls = re.sub(r"[^a-z]+", "-", value.lower()).strip("-") or "unknown"
    return '<span class="badge %s-%s">%s</span>' % (kind, cls, html.escape(value))


# ================================================================ build
def build(src, dst):
    src, dst = pathlib.Path(src).resolve(), pathlib.Path(dst)
    root = pathlib.Path(__file__).resolve().parent.parent
    if dst.exists():
        shutil.rmtree(dst)
    (dst / "advisories").mkdir(parents=True)
    shutil.copytree(root / "site" / "assets", dst / "assets")

    files = sorted(p for p in src.iterdir() if p.is_file() and not p.name.startswith(("~$", ".")))
    chosen = {}
    for path in files:
        ext = path.suffix.lower()
        if ext not in (".md", ".docx"):
            if ext in (".doc", ".docm", ".odt", ".rtf", ".pdf"):
                warn(path, "unsupported format %s; save it as .docx" % ext)
            continue
        found = CVE_ID.search(path.stem)
        key = found.group(0).upper() if found else path.stem.lower()
        if key in chosen:
            keep = path if ext == ".docx" else chosen[key]
            warn(path, "two files for %s; publishing %s" % (key, keep.name))
            chosen[key] = keep
        else:
            chosen[key] = path

    items = []
    for key, path in sorted(chosen.items()):
        try:
            meta, body_html, first = (read_docx(path) if path.suffix.lower() == ".docx"
                                      else read_markdown(path))
        except Exception as exc:  # never let one file break the site
            warn(path, "could not read this file (%s)" % exc)
            meta, first = {"status": "Identify"}, ""
            body_html = ("<p><strong>This advisory file could not be read.</strong> "
                         "InfoSec has been notified in the build log.</p>")
        meta = finish_meta(meta, path, first)
        out_name = meta["id"] if CVE_ID.fullmatch(meta["id"]) else \
            re.sub(r"[^A-Za-z0-9._-]+", "-", path.stem) or "advisory"
        fields = "".join(
            "<div><dt>%s</dt><dd>%s</dd></div>" % (k, v)
            for k, v in [("Severity", badge("sev", meta["severity"])),
                         ("Stage", badge("st", meta["status"])),
                         ("Published", html.escape(meta["published"])),
                         ("Updated", html.escape(meta["updated"]))])
        summary = '<p class="summary">%s</p>' % inline(meta["summary"]) if meta["summary"] else ""
        content = ('<p class="back"><a href="../index.html">&larr; All advisories</a></p>'
                   '<h1>%s &ndash; %s</h1><dl class="meta">%s</dl>%s%s'
                   % (html.escape(meta["id"]), html.escape(meta["name"]), fields, summary, body_html))
        (dst / "advisories" / (out_name + ".html")).write_text(
            page(meta["id"] + " " + meta["name"], content, 1), encoding="utf-8")
        meta["_file"] = out_name
        items.append(meta)

    items.sort(key=lambda m: m["updated"] if re.fullmatch(r"\d{4}-\d{2}-\d{2}", m["updated"]) else "",
               reverse=True)
    rows = "".join(
        '<tr><td><a href="advisories/%s.html">%s</a></td><td>%s</td><td>%s</td><td>%s</td>'
        "<td>%s</td><td>%s</td><td>%s</td></tr>"
        % (html.escape(m["_file"]), html.escape(m["id"]), html.escape(m["name"]),
           badge("sev", m["severity"]), badge("st", m["status"]), html.escape(m["published"]),
           html.escape(m["updated"]), inline(m["summary"]))
        for m in items)
    index = (
        "<h1>Security advisories</h1>"
        "<p>Company-wide vulnerabilities analysed by InfoSec. Open an advisory for the technical "
        "details, how to check your systems and how to fix them. Report your product line status "
        "on the Confluence Inventory page linked inside each advisory. Stage shows the current "
        "response stage: Identify, Prioritize, Remediate, Monitor or Closed.</p>"
        '<div class="table"><table class="index"><thead><tr><th>CVE</th><th>Name</th><th>Severity</th>'
        "<th>Stage</th><th>Published</th><th>Updated</th><th>Summary</th></tr></thead>"
        "<tbody>%s</tbody></table></div>" % rows)
    prio = root / "site" / "priority.md"
    if prio.exists():
        try:
            index += '<section class="priority">%s</section>' % md_to_html(
                prio.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:
            warn(prio, "could not format priority.md (%s); left out" % exc)
    (dst / "index.html").write_text(page("Security advisories", index, 0), encoding="utf-8")
    print("Built %d advisories into %s (%d warnings)" % (len(items), dst, len(WARNINGS)))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    build(sys.argv[1], sys.argv[2])
