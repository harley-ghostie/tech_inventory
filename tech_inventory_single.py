#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r"""
Tech Inventory (single-file)
- No wappalyzer install.
- Uses local Wappalyzer-style fingerprints.
- Supports:
  (A) Single file: technologies.json (top-level JSON object/dict)
  (B) Directory: src/technologies/*.json (many files, merged into one dict)
- Optional: categories.json

Behavior:
- Never stops on a single URL failure. Records errors and continues.

Outputs:
- per_url.json: url -> {tech: {version, confidence, categories}}
- grouped_by_category.json: category -> tech -> version -> urls
- errors.json: url -> {error_type, message}
"""

import argparse
import json
import random
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests


# -------------------------
# User-Agent pool (simple)
# -------------------------
UA_POOL = [
    # Chrome Win
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Firefox Win
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Firefox Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Safari macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]


# -------------------------
# Pattern parsing (Wappalyzer-like)
# -------------------------

@dataclass
class CompiledPattern:
    regex: re.Pattern
    confidence: int = 100
    version_template: Optional[str] = None


def _compile_one_pattern(p: str) -> CompiledPattern:
    """
    Pattern string may contain tags like:
      "jquery-([0-9.]+)\\.js;confidence:50;version:\\1"
    We parse:
      - base regex
      - confidence:<int>
      - version:<template> (supports \\1..\\9)
    """
    confidence = 100
    version_template = None

    parts = p.split(";")
    base = (parts[0] if parts else "").strip()
    tags = [x.strip() for x in parts[1:] if x.strip()]

    for t in tags:
        m = re.match(r"(?i)confidence\s*:\s*(\d+)", t)
        if m:
            confidence = int(m.group(1))
            continue
        m = re.match(r"(?i)version\s*:\s*(.+)", t)
        if m:
            version_template = m.group(1).strip()
            continue

    if not base:
        base = ".*"

    try:
        rgx = re.compile(base, re.IGNORECASE)
    except re.error:
        rgx = re.compile(re.escape(base), re.IGNORECASE)

    return CompiledPattern(regex=rgx, confidence=confidence, version_template=version_template)


def _normalize_patterns(value: Any) -> List[CompiledPattern]:
    if value is None:
        return []
    if isinstance(value, str):
        return [_compile_one_pattern(value)]
    if isinstance(value, list):
        out: List[CompiledPattern] = []
        for v in value:
            if isinstance(v, str):
                out.append(_compile_one_pattern(v))
        return out
    return []


def _render_version(tpl: str, match: re.Match) -> str:
    v = tpl
    for i in range(1, 10):
        rep = ""
        if match.lastindex and i <= match.lastindex:
            rep = match.group(i) or ""
        v = v.replace(f"\\{i}", rep)
    return v.strip()


# -------------------------
# Fingerprints loading
# -------------------------

@dataclass
class TechRule:
    name: str
    cats: List[int]
    headers: Dict[str, List[CompiledPattern]]
    cookies: Dict[str, List[CompiledPattern]]
    meta: Dict[str, List[CompiledPattern]]
    html: List[CompiledPattern]
    script_src: List[CompiledPattern]


def _read_json_file(path: Path) -> Any:
    txt = path.read_text(encoding="utf-8", errors="replace").strip()
    if txt.startswith("404:") or txt.lower().startswith("<!doctype") or txt.lower().startswith("<html"):
        raise ValueError(
            f"Arquivo {path} não parece JSON. Começo do arquivo:\n{txt[:200]!r}\n"
            f"Isso geralmente é download errado (ex: 404)."
        )
    try:
        return json.loads(txt)
    except json.JSONDecodeError as e:
        raise ValueError(
            f"Falha ao parsear JSON em {path}: {e}\n"
            f"Começo do arquivo: {txt[:200]!r}"
        ) from e


def load_technologies(technologies_path: str) -> Dict[str, Any]:
    p = Path(technologies_path)

    if p.is_dir():
        merged: Dict[str, Any] = {}
        files = sorted([x for x in p.glob("*.json") if x.is_file()])
        if not files:
            raise FileNotFoundError(f"Nenhum *.json encontrado dentro do diretório: {p}")

        for f in files:
            raw = _read_json_file(f)
            if isinstance(raw, dict):
                merged.update(raw)

        if not merged:
            raise ValueError(f"Diretório {p} não gerou tecnologias (dict vazio).")
        return merged

    if p.is_file():
        raw = _read_json_file(p)
        if not isinstance(raw, dict):
            raise ValueError("technologies.json inválido: esperado objeto JSON (dict) no topo.")
        return raw

    raise FileNotFoundError(f"Technologies path não existe: {p}")


def load_fingerprints(technologies_path: str) -> Dict[str, TechRule]:
    raw = load_technologies(technologies_path)

    techs: Dict[str, TechRule] = {}
    for tech_name, rule in raw.items():
        if not isinstance(rule, dict):
            continue

        cats = rule.get("cats") or []
        if isinstance(cats, list):
            cats = [int(x) for x in cats if str(x).isdigit()]
        else:
            cats = []

        headers = {}
        for hk, hv in (rule.get("headers") or {}).items():
            headers[str(hk).lower()] = _normalize_patterns(hv)

        cookies = {}
        for ck, cv in (rule.get("cookies") or {}).items():
            cookies[str(ck).lower()] = _normalize_patterns(cv)

        meta = {}
        for mk, mv in (rule.get("meta") or {}).items():
            meta[str(mk).lower()] = _normalize_patterns(mv)

        html = _normalize_patterns(rule.get("html"))
        script_src = _normalize_patterns(rule.get("scriptSrc"))

        techs[str(tech_name)] = TechRule(
            name=str(tech_name),
            cats=cats,
            headers=headers,
            cookies=cookies,
            meta=meta,
            html=html,
            script_src=script_src,
        )

    return techs


def load_categories(categories_path: Optional[str]) -> Dict[int, str]:
    if not categories_path:
        return {}

    p = Path(categories_path)
    if not p.exists():
        return {}

    raw = _read_json_file(p)
    out: Dict[int, str] = {}

    if isinstance(raw, dict):
        if "categories" in raw and isinstance(raw["categories"], dict):
            for k, v in raw["categories"].items():
                if str(k).isdigit():
                    out[int(k)] = str(v)
            return out

        for k, v in raw.items():
            if str(k).isdigit():
                if isinstance(v, dict) and "name" in v:
                    out[int(k)] = str(v["name"])
                elif isinstance(v, str):
                    out[int(k)] = v

    return out


# -------------------------
# File resolving helpers
# -------------------------

def resolve_fingerprints(fp_dir: Optional[str], technologies: Optional[str], categories: Optional[str]) -> Tuple[str, Optional[str]]:
    candidates: List[str] = []
    if technologies:
        candidates.append(technologies)

    if fp_dir:
        d = Path(fp_dir)
        candidates += [
            str(d / "technologies.json"),
            str(d / "src" / "technologies"),
            str(d / "technologies"),
        ]

    candidates += [
        "./src/technologies",
        "./technologies",
        "./fingerprints/technologies.json",
        "./technologies.json",
        "../src/technologies",
        "../fingerprints/technologies.json",
    ]

    tech_path = None
    for c in candidates:
        p = Path(c)
        if p.exists():
            tech_path = str(p)
            break

    if not tech_path:
        raise FileNotFoundError(
            "Não encontrei fingerprints de tecnologias.\n"
            "Precisa de UM destes:\n"
            "  - technologies.json (arquivo)\n"
            "  - src/technologies/*.json (diretório)\n"
            "Use: --technologies <caminho> ou --fingerprints-dir <dir>"
        )

    cat_path = None
    cat_candidates: List[str] = []
    if categories:
        cat_candidates.append(categories)
    if fp_dir:
        d = Path(fp_dir)
        cat_candidates += [
            str(d / "categories.json"),
            str(d / "src" / "categories.json"),
        ]
    cat_candidates += [
        "./categories.json",
        "./fingerprints/categories.json",
        "./src/categories.json",
        "../fingerprints/categories.json",
    ]
    for c in cat_candidates:
        p = Path(c)
        if p.exists():
            cat_path = str(p)
            break

    return tech_path, cat_path


# -------------------------
# Scanner
# -------------------------

@dataclass
class Detection:
    version: str = ""
    confidence: int = 0
    categories: List[str] = None


def _pick_ua(fixed_ua: str, random_ua: bool) -> str:
    if random_ua:
        return random.choice(UA_POOL)
    return fixed_ua


def fetch_url(
    url: str,
    timeout: int,
    user_agent: str,
    cookies: str = "",
    retries: int = 0,
    backoff: float = 0.0,
) -> Tuple[requests.Response, str]:
    headers = {"User-Agent": user_agent}
    if cookies:
        headers["Cookie"] = cookies

    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
            try:
                body = r.text or ""
            except Exception:
                body = ""
            return r, body
        except requests.RequestException as e:
            last_exc = e
            if attempt < retries and backoff > 0:
                time.sleep(backoff * (attempt + 1))
            continue

    raise last_exc if last_exc else RuntimeError("Falha desconhecida em fetch_url")


def extract_meta(body: str) -> Dict[str, str]:
    metas = {}
    for m in re.finditer(
        r'<meta[^>]+(?:name|property)\s*=\s*["\']([^"\']+)["\'][^>]+content\s*=\s*["\']([^"\']*)["\']',
        body,
        re.IGNORECASE,
    ):
        k = m.group(1).strip().lower()
        v = m.group(2).strip()
        if k and k not in metas:
            metas[k] = v
    return metas


def extract_script_src(body: str) -> List[str]:
    srcs = []
    for m in re.finditer(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', body, re.IGNORECASE):
        srcs.append(m.group(1).strip())
    return srcs


def scan_one(
    url: str,
    tech_rules: Dict[str, TechRule],
    cat_map: Dict[int, str],
    timeout: int,
    ua: str,
    cookie: str,
    retries: int,
    backoff: float,
) -> Dict[str, Detection]:
    r, body = fetch_url(
        url=url,
        timeout=timeout,
        user_agent=ua,
        cookies=cookie,
        retries=retries,
        backoff=backoff,
    )

    headers = {k.lower(): v for k, v in r.headers.items()}
    cookie_names = [c.name.lower() for c in r.cookies]
    meta = extract_meta(body)
    script_srcs = extract_script_src(body)

    found: Dict[str, Detection] = {}

    def ensure_det(tech_name: str, cats: List[int]) -> Detection:
        if tech_name not in found:
            cat_names = []
            for cid in cats:
                cat_names.append(cat_map.get(cid, f"cat:{cid}"))
            found[tech_name] = Detection(version="", confidence=0, categories=cat_names)
        return found[tech_name]

    for tech_name, rule in tech_rules.items():
        # headers
        for hk, patterns in rule.headers.items():
            hv = headers.get(hk, "")
            if not hv:
                continue
            for p in patterns:
                m = p.regex.search(hv)
                if m:
                    det = ensure_det(tech_name, rule.cats)
                    det.confidence = min(100, det.confidence + p.confidence)
                    if p.version_template:
                        v = _render_version(p.version_template, m)
                        if v:
                            det.version = v

        # cookies (presence)
        for ck, patterns in rule.cookies.items():
            if ck not in cookie_names:
                continue
            det = ensure_det(tech_name, rule.cats)
            if not patterns:
                det.confidence = min(100, det.confidence + 100)
            else:
                for p in patterns:
                    det.confidence = min(100, det.confidence + p.confidence)

        # meta
        for mk, patterns in rule.meta.items():
            mv = meta.get(mk, "")
            if not mv:
                continue
            for p in patterns:
                m = p.regex.search(mv)
                if m:
                    det = ensure_det(tech_name, rule.cats)
                    det.confidence = min(100, det.confidence + p.confidence)
                    if p.version_template:
                        v = _render_version(p.version_template, m)
                        if v:
                            det.version = v

        # html
        for p in rule.html:
            m = p.regex.search(body)
            if m:
                det = ensure_det(tech_name, rule.cats)
                det.confidence = min(100, det.confidence + p.confidence)
                if p.version_template:
                    v = _render_version(p.version_template, m)
                    if v:
                        det.version = v

        # scriptSrc
        if rule.script_src and script_srcs:
            joined = "\n".join(script_srcs)
            for p in rule.script_src:
                m = p.regex.search(joined)
                if m:
                    det = ensure_det(tech_name, rule.cats)
                    det.confidence = min(100, det.confidence + p.confidence)
                    if p.version_template:
                        v = _render_version(p.version_template, m)
                        if v:
                            det.version = v

    return {k: v for k, v in found.items() if v.confidence > 0}


def group_results(per_url: Dict[str, Dict[str, Detection]]) -> List[Dict[str, Any]]:
    grouped = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    for url, techs in per_url.items():
        for tech_name, det in techs.items():
            version_key = det.version.strip() if det.version else "unknown"
            categories = det.categories or ["Unknown"]
            for c in categories:
                grouped[c][tech_name][version_key].add(url)

    out = []
    for category, tech_map in grouped.items():
        items = []
        for tech_name, ver_map in tech_map.items():
            for ver, urls in ver_map.items():
                items.append({
                    "technology": tech_name,
                    "version": ver,
                    "count": len(urls),
                    "urls": sorted(urls),
                })
        items.sort(key=lambda x: (x["technology"].lower(), x["version"].lower()))
        out.append({"category": category, "items": items})

    out.sort(key=lambda x: x["category"].lower())
    return out


def read_urls(path: Optional[str]) -> List[str]:
    if path:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    else:
        lines = sys.stdin.read().splitlines()

    urls = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not re.match(r"^https?://", line, re.IGNORECASE):
            line = "https://" + line
        urls.append(line)
    return urls


def main():
    ap = argparse.ArgumentParser(description="Tech inventory scan (single-file, no wappalyzer install).")
    ap.add_argument("-i", "--input", help="File with URLs (one per line). If omitted, reads stdin.")
    ap.add_argument("--fingerprints-dir", help="Dir containing technologies.json OR src/technologies/*.json (+ optional categories.json).")
    ap.add_argument("--technologies", help="Path to technologies.json OR a directory like src/technologies/")
    ap.add_argument("--categories", help="Path to categories.json (optional).")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--user-agent", default="ReconTechInventory/1.0", help="Fixed User-Agent (default: ReconTechInventory/1.0)")
    ap.add_argument("--random-ua", action="store_true", help="Use a random User-Agent per request")
    ap.add_argument("--cookie", default="", help='Optional Cookie header string, e.g. "session=abc; token=xyz"')

    ap.add_argument("--confidence-min", type=int, default=50)

    ap.add_argument("--retries", type=int, default=1, help="Retries per URL on request failure")
    ap.add_argument("--backoff", type=float, default=0.8, help="Backoff base seconds (multiplies per attempt)")

    ap.add_argument("--rate-limit", type=float, default=0.05, help="Base sleep between URLs (seconds)")
    ap.add_argument("--jitter", type=float, default=0.05, help="Adds random 0..jitter seconds to sleep")

    ap.add_argument("--out-per-url", default="per_url.json")
    ap.add_argument("--out-grouped", default="grouped_by_category.json")
    ap.add_argument("--out-errors", default="errors.json")
    args = ap.parse_args()

    urls = read_urls(args.input)

    tech_path, cat_path = resolve_fingerprints(
        fp_dir=args.fingerprints_dir,
        technologies=args.technologies,
        categories=args.categories,
    )

    tech_rules = load_fingerprints(tech_path)
    cat_map = load_categories(cat_path)

    per_url: Dict[str, Dict[str, Detection]] = {}
    errors: Dict[str, Dict[str, str]] = {}

    for url in urls:
        ua = _pick_ua(args.user_agent, args.random_ua)

        try:
            dets = scan_one(
                url=url,
                tech_rules=tech_rules,
                cat_map=cat_map,
                timeout=args.timeout,
                ua=ua,
                cookie=args.cookie,
                retries=args.retries,
                backoff=args.backoff,
            )
            dets = {k: v for k, v in dets.items() if v.confidence >= args.confidence_min}
            per_url[url] = dets
        except requests.exceptions.RequestException as e:
            errors[url] = {"error_type": e.__class__.__name__, "message": str(e)}
            per_url[url] = {}
        except Exception as e:
            errors[url] = {"error_type": e.__class__.__name__, "message": str(e)}
            per_url[url] = {}

        # polite pacing
        sleep_for = max(0.0, args.rate_limit) + (random.random() * max(0.0, args.jitter))
        time.sleep(sleep_for)

    per_url_json = {}
    for url, techs in per_url.items():
        per_url_json[url] = {
            tech: {
                "version": d.version,
                "confidence": d.confidence,
                "categories": d.categories or [],
            }
            for tech, d in techs.items()
        }

    grouped = group_results(per_url)

    Path(args.out_per_url).write_text(json.dumps(per_url_json, ensure_ascii=False, indent=2), encoding="utf-8")
    Path(args.out_grouped).write_text(json.dumps(grouped, ensure_ascii=False, indent=2), encoding="utf-8")
    Path(args.out_errors).write_text(json.dumps(errors, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"OK: {args.out_per_url}, {args.out_grouped}, {args.out_errors} gerados.")
    print(f"Fingerprints usados:\n  technologies: {tech_path}\n  categories:   {cat_path or '(não encontrado/omitido)'}")
    if errors:
        print(f"Aviso: {len(errors)} URLs falharam. Veja {args.out_errors}.")


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
