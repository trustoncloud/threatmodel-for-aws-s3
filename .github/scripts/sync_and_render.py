from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import shutil
import subprocess
import re
from subprocess import Popen
import urllib.parse
import time
import zlib
from bs4 import BeautifulSoup as BS4
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Tuple
from copy import deepcopy
from dataclasses import dataclass

from aws_session import client as aws_client
from botocore.exceptions import ClientError
from search_dataset import build_and_upload_search_dataset

# Diagnostics helpers for filesystem visibility
def safe_listdir(p: Path) -> list[str]:
    try:
        return sorted([e.name for e in p.iterdir()])
    except Exception:
        return []

def log_path_debug(label: str, p: Path) -> None:
    try:
        exists = p.exists()
        size = p.stat().st_size if exists else -1
        readable = os.access(p, os.R_OK)
        logger.debug("%s: %s exists=%s size=%s readable=%s", label, p, exists, size, readable)
    except Exception as e:
        logger.debug("%s: %s stat error: %s", label, p, e)


level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
level = getattr(logging, level_name, logging.INFO)
logging.basicConfig(level=level)
logger = logging.getLogger("etl-sync")
logger.info("Log level set to %s", logging.getLevelName(level))

class DrawioExportHardFailure(RuntimeError):
    """Raised when draw.io export exhausts all strategies without producing output."""
    pass

# Filter and fatal patterns mirroring the working GitHub Action logs handling
FILTER_PATTERNS = re.compile(
    r"(Failed to connect to the bus|Checking for beta autoupdate feature|Found package-type|Exiting GPU process|Failed to send GpuControl\.CreateCommandBuffer)",
    re.IGNORECASE,
)
FATAL_PATTERNS = re.compile(
    r"(Missing X server|DISPLAY.*not set|The platform failed to initialize|authorization required|No protocol specified)",
    re.IGNORECASE,
)


def env_str(name: str, default: str | None = None, required: bool = False) -> str:
    val = os.environ.get(name, default)
    if required and (val is None or not str(val).strip()):
        raise RuntimeError(f"Missing required ENV: {name}")
    return (val or "").strip()


# API key retrieval is handled by the Lambda proxy; container does not read SSM directly.


def execute_get(url: str) -> Dict[str, Any]:
    """
    Execute GET via the Lambda proxy (API_PROXY_FUNCTION must be set).
    Returns a dict with keys: status, body, headers.
    """
    fn = os.environ.get("API_PROXY_FUNCTION", "").strip()
    if not fn:
        raise RuntimeError("API_PROXY_FUNCTION is not set; Lambda proxy is required")
    lam = aws_client("lambda")
    payload = {"url": url, "method": "GET"}
    resp = lam.invoke(
        FunctionName=fn,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode("utf-8"),
    )
    out_raw = resp.get("Payload").read().decode("utf-8")
    try:
        out = json.loads(out_raw)
    except Exception:
        out = {"statusCode": 502, "body": out_raw}
    body = out.get("body")
    if isinstance(body, str):
        try:
            body_json = json.loads(body)
        except Exception:
            body_json = body
    else:
        body_json = body
    status = out.get("statusCode") or out.get("status") or 200
    if int(status) >= 400:
        logger.warning("API proxy returned %s for %s: %s", status, url, body_json)
    return {"status": status, "reason": "", "headers": {}, "body": body_json}


def s3_read_json(bucket: str, key: str) -> Dict[str, Any]:
    s3 = aws_client("s3")
    try:
        obj = s3.get_object(Bucket=bucket, Key=key)
        data = obj["Body"].read().decode("utf-8")
        return json.loads(data)
    except ClientError as e:
        code = (e.response or {}).get("Error", {}).get("Code")
        if code == "NoSuchKey":
            return {}
        logger.warning(f"Failed to read s3://{bucket}/{key}: {e}")
        return {}
    except Exception as e:
        logger.warning(f"Failed to parse s3://{bucket}/{key} as JSON: {e}")
        return {}


def s3_write_json(bucket: str, key: str, data: Dict[str, Any]) -> None:
    s3 = aws_client("s3")
    body = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="application/json")


def body_sha256(b64_body: str) -> str:
    try:
        raw = base64.b64decode(b64_body)
    except Exception:
        raw = b64_body.encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()


def run_cmd(args: List[str], cwd: str | None = None) -> None:
    logger.debug("Running: %s", " ".join(args))
    subprocess.run(args, check=True, cwd=cwd)

def run_cmd_capture(args: List[str], cwd: str | None = None) -> subprocess.CompletedProcess[str]:
    logger.debug("Running: %s", " ".join(args))
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True)


def debug_log_drawio_version() -> None:
    """
    Try to log draw.io version if available.
    """
    try:
        cp = run_cmd_capture(["drawio", "--version"])
        if cp.returncode == 0:
            out = (cp.stdout or cp.stderr or "").strip()
            if out:
                logger.debug("drawio --version: %s", out.replace("\n", " | "))
        else:
            logger.debug("drawio --version returned code %s", cp.returncode)
    except Exception as e:
        logger.debug("drawio --version not available: %s", e)


def start_xvfb() -> Popen[bytes]:
    """
    Start a single Xvfb server and configure environment.
    """
    proc = Popen(["Xvfb", ":99", "-screen", "0", "3840x2160x24", "-nolisten", "tcp", "-ac"])
    os.environ["DISPLAY"] = ":99.0"
    os.environ.setdefault("LIBGL_ALWAYS_SOFTWARE", "1")
    os.environ.setdefault("NO_AT_BRIDGE", "1")
    os.environ.pop("XAUTHORITY", None)
    os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)
    os.environ.pop("DBUS_SYSTEM_BUS_ADDRESS", None)
    return proc


def stop_xvfb(proc: Popen[bytes]) -> None:
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def inspect_mxfile(path: Path) -> None:
    """
    Inspect a .drawio/.xml file and log diagnostic information about:
    - number of <diagram> pages
    - whether the first diagram contains embedded XML or base64 text
    - ability to base64-decode and deflate-decompress (if applicable)
    - counts of <mxCell> and <object> under <root> when possible
    """
    try:
        txt = path.read_text(encoding="utf-8", errors="ignore")
        soup = BS4(txt, "xml")
        top_diagrams = soup.select("mxfile > diagram")
        logger.debug("Inspecting %s: top_level_diagrams=%d", path.name, len(top_diagrams))
        if not top_diagrams:
            return
        d = top_diagrams[0]
        # Embedded XML?
        has_mx = d.find("mxGraphModel") is not None
        raw_text = (d.text or "").strip()
        logger.debug("First diagram embedded_xml=%s text_len=%d", has_mx, len(raw_text))
        if not has_mx and raw_text:
            # Try base64 decode and deflate
            try:
                dec = base64.b64decode(raw_text)
                logger.debug("Base64 decode ok: %d bytes", len(dec))
                # Try deflate
                try:
                    decomp = zlib.decompress(dec, -zlib.MAX_WBITS)
                    logger.debug("Deflate decompress ok: %d bytes", len(decomp))
                    # Try parse decompressed to count elements
                    inner = BS4(urllib.parse.unquote(decomp.decode("utf-8", errors="ignore")), "xml")
                    root = inner.select_one("root")
                    mxcells = len(inner.select("root > mxCell"))
                    objects = len(inner.select("root > object"))
                    logger.debug("Decompressed XML stats: root=%s mxCells=%d objects=%d",
                                bool(root), mxcells, objects)
                except Exception as e:
                    logger.debug("Deflate decompress failed: %s", e)
                    # Check if plain XML inside base64
                    try:
                        as_txt = dec.decode("utf-8", errors="ignore")
                        looks_xml = ("<mxGraphModel" in as_txt) or ("<mxfile" in as_txt) or as_txt.lstrip().startswith("<")
                        logger.debug("Decoded bytes look like plain XML: %s", looks_xml)
                    except Exception as e2:
                        logger.info("Decoded bytes not valid UTF-8 XML: %s", e2)
            except Exception as e:
                logger.debug("Base64 decode failed for diagram text: %s", e)
        else:
            # Count elements directly from embedded model (scoped to the first top-level diagram)
            root = d.select_one("root")
            mxcells = len(d.select("root > mxCell"))
            objects = len(d.select("root > object"))
            logger.debug("Embedded XML stats: root=%s mxCells=%d objects=%d", bool(root), mxcells, objects)
    except Exception as e:
        logger.info("inspect_mxfile error for %s: %s", path, e)

def write_decompressed_main(src_xml: Path, dest_xml: Path) -> None:
    """
    Always expect <diagram> text to be decoded, then:
      - try deflate decompression first; if that fails, treat decoded bytes as plain XML
      - extract and embed a <mxGraphModel> into the <diagram>
    Normalize flags so draw.io CLI does not misinterpret:
      - set mxfile.compressed="false"
      - remove diagram.compressed attribute
    Raise on unexpected formats instead of keeping encoded payload.
    """
    logger.debug("Preparing main XML: attempting to decompress diagram content from %s", src_xml)
    try:
        txt: str = src_xml.read_text(encoding="utf-8")
        soup = BS4(txt, "xml")
        diagram_tag = soup.select_one("diagram")
        if not diagram_tag:
            raise ValueError("Expected <diagram> with base64 content, but none found")

        # Nothing to do if diagram already decompreseed as it contains an mxGraphModel
        if diagram_tag.find("mxGraphModel") is not None:
            # normalize flags even for already-embedded cases
            mxfile = soup.select_one("mxfile")
            if mxfile is not None:
                mxfile["compressed"] = "false"
            if "compressed" in diagram_tag.attrs:
                del diagram_tag["compressed"]
            dest_xml.write_text(str(soup), encoding="utf-8")
            return

        # Decode inner diagram content from base64, then try deflate; fallback to plain XML
        enc_text = (diagram_tag.text or "").strip()
        if not enc_text:
            raise ValueError("Diagram has no text content to decode")

        try:
            decoded_bytes = base64.b64decode(enc_text)
        except Exception as e:
            raise ValueError(f"Diagram text is not valid base64: {e}")

        def _extract_graph(xml_text: str):
            inner = BS4(xml_text, "xml")
            graph = inner.find("mxGraphModel")
            if not graph:
                graph = inner.select_one("mxfile > diagram > mxGraphModel")
                if not graph:
                    # Try nested base64/deflate inside inner <mxfile><diagram>
                    inner_diagram = inner.select_one("mxfile > diagram")
                    if inner_diagram:
                        inner_text = (inner_diagram.text or "").strip()
                        if inner_text:
                            try:
                                dec2 = base64.b64decode(inner_text)
                                try:
                                    xml2 = urllib.parse.unquote(zlib.decompress(dec2, -zlib.MAX_WBITS).decode("utf-8"))
                                except Exception:
                                    xml2 = dec2.decode("utf-8", errors="ignore")
                                inner2 = BS4(xml2, "xml")
                                graph = inner2.find("mxGraphModel") or inner2.select_one("mxfile > diagram > mxGraphModel")
                            except Exception:
                                pass
            return graph

        graph = None
        # First, attempt deflate (draw.io compressed form)
        try:
            decompressed_xml = urllib.parse.unquote(zlib.decompress(decoded_bytes, -zlib.MAX_WBITS).decode("utf-8"))
            graph = _extract_graph(decompressed_xml)
        except Exception:
            pass

        # Fallback: treat decoded bytes as plain XML
        if graph is None:
            try:
                as_text = decoded_bytes.decode("utf-8", errors="ignore")
                graph = _extract_graph(as_text)
            except Exception:
                pass

        if not graph:
            raise ValueError("Failed to obtain <mxGraphModel> from diagram content")

        diagram_tag.clear()
        diagram_tag.append(graph)
        mxfile = soup.select_one("mxfile")
        if mxfile is not None:
            mxfile["compressed"] = "false"
        if "compressed" in diagram_tag.attrs:
            del diagram_tag["compressed"]
        dest_xml.write_text(str(soup), encoding="utf-8")
        return

    except Exception as e:
        raise ValueError(f"Failed to process main XML: {str(e)}")

def drawio_export(input_path: Path, output_path: Path, width: int) -> None:
    if not input_path.exists():
        raise FileNotFoundError(f"drawio input does not exist: {input_path}")
    out_dir = output_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    # Use a .drawio path (create a temporary copy if needed)
    temp_copy: Path | None = None
    inp = input_path
    if input_path.suffix.lower() != ".drawio":
        temp_copy = input_path.with_suffix(".drawio")
        shutil.copy2(input_path, temp_copy)
        inp = temp_copy

    # Use the invocation that works on this draw.io build: input first, long flags
    cmd = [
        "drawio",
        str(inp),
        "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", "--no-plugins",
        "--export", "--format", "png", "--width", str(width),
        "--output", str(output_path),
    ]

    # Pre-export diagnostics
    log_path_debug("Pre-export input", inp)
    logger.debug("Pre-export listdir input_dir=%s -> %s", inp.parent, safe_listdir(inp.parent))
    logger.debug("Pre-export listdir out_dir=%s -> %s", out_dir, safe_listdir(out_dir))
    logger.info("Attempting draw.io export: input=%s output=%s", inp, output_path)

    MAX_RETRIES = 3
    for attempt in range(1, MAX_RETRIES + 1):
        cp = subprocess.run(cmd, text=True, capture_output=True)
        combined = ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip()
        # Log output with filtering: hide noisy lines, surface fatals, keep the rest at debug.
        for line in combined.splitlines():
            if not line.strip():
                continue
            if FATAL_PATTERNS.search(line):
                logger.error("drawio: %s", line)
            elif FILTER_PATTERNS.search(line):
                continue
            else:
                logger.debug("drawio: %s", line)
        if cp.returncode != 0:
            filtered_tail = "\n".join(
                [ln for ln in combined.splitlines() if not FILTER_PATTERNS.search(ln)]
            )[-2000:]
            logger.warning(
                'drawio failed (attempt %d/%d, rc=%d) for "%s": %s',
                attempt,
                MAX_RETRIES,
                cp.returncode,
                inp,
                filtered_tail,
            )
            if attempt < MAX_RETRIES:
                continue
            raise RuntimeError(f"drawio export failed after {MAX_RETRIES} attempts for {input_path}")
        break

    if not output_path.exists():
        raise RuntimeError(f"drawio export did not produce expected file: {output_path}")
    size = output_path.stat().st_size
    if size <= 0:
        raise RuntimeError(f"drawio export produced empty file: {output_path} (size={size})")
    logger.info("drawio export succeeded: %s (size=%d bytes)", output_path, size)

    if temp_copy and temp_copy.exists():
        try:
            temp_copy.unlink()
        except Exception:
            pass


def generate_variants_and_render(src_xml: Path, out_dir: Path, manage_xvfb: bool = False) -> Tuple[List[Path], List[Path]]:
    # Ensure software rendering for headless environments
    os.environ.setdefault("LIBGL_ALWAYS_SOFTWARE", "1")
    os.environ.setdefault("NO_AT_BRIDGE", "1")
    os.environ.setdefault("DRAWIO_DISABLE_UPDATE", "1")
    os.environ.setdefault("ELECTRON_DISABLE_SANDBOX", "1")
    for k in ("DBUS_SESSION_BUS_ADDRESS", "DBUS_SYSTEM_BUS_ADDRESS"):
        os.environ.pop(k, None)
    # Start a single Xvfb server

    work_root = src_xml.parent
    to_convert = work_root / "to_convert"
    main_dir = to_convert / "main_dfd"
    fc_dir = to_convert / "fc_dfd"
    threat_dir = to_convert / "threat_dfd"
    for d in (main_dir, fc_dir, threat_dir, out_dir):
        d.mkdir(parents=True, exist_ok=True)

    # Prepare main XML: decompress diagram content if possible
    write_decompressed_main(src_xml, main_dir / src_xml.name)

    # Inspect the prepared XML for diagnostics
    inspect_mxfile(main_dir / src_xml.name)

    xvfb_proc = start_xvfb() if manage_xvfb else None
    try:
        if xvfb_proc is not None:
            time.sleep(0.5)

        # Create FC and Threat variants with validation
        run_cmd(
            [
                "python",
                "/app/threat_opacity_xml_creator.py",
                str(main_dir / src_xml.name),
                "--threat-dir",
                str(threat_dir),
                "--fc-dir",
                str(fc_dir),
                "--validate",
            ]
        )

        # Render main DFD (higher width)
        out_png_main = out_dir / f"{src_xml.stem}.png"
        inp_main = main_dir / src_xml.name
        if not inp_main.exists():
            raise FileNotFoundError(f"Main input XML not found: {inp_main}")
        # Robust draw.io export
        drawio_export(inp_main, out_png_main, width=1500)

        # Render other XMLs
        for sub in (fc_dir, threat_dir):
            xml_list = sorted(sub.glob("*.xml"))
            logger.info("Will render %d PNG(s) from %s", len(xml_list), sub)
            for xml in xml_list:
                out_png = out_dir / f"{xml.stem}.png"
                drawio_export(xml, out_png, width=1200)

        pngs = sorted(out_dir.glob("*.png"))
        # Collect XMLs to upload/inventory: main + generated FC/Threat XMLs
        xmls: List[Path] = [inp_main] + sorted(fc_dir.glob("*.xml")) + sorted(threat_dir.glob("*.xml"))
        return pngs, xmls
    finally:
        if xvfb_proc is not None:
            stop_xvfb(xvfb_proc)


def upload_images(s3_bucket: str, s3_prefix: str, files: List[Path]) -> None:
    s3 = aws_client("s3")
    for f in files:
        dashed_name = f.name.replace("_", "-")
        key = f"{s3_prefix.rstrip('/')}/img/{dashed_name}"
        logger.info("Uploading %s to s3://%s/%s", dashed_name, s3_bucket, key)
        s3.upload_file(str(f), s3_bucket, key)

def upload_xmls(s3_bucket: str, s3_prefix: str, files: List[Path]) -> None:
    s3 = aws_client("s3")
    for f in files:
        key = f"{s3_prefix.rstrip('/')}/xml/{f.name}"
        logger.info("Uploading XML %s to s3://%s/%s", f.name, s3_bucket, key)
        s3.upload_file(str(f), s3_bucket, key)


def s3_scan_existing_versions(bucket: str, dataset_prefix: str) -> set[tuple[str, str]]:
    """
    Scan S3 once under the given dataset_prefix and return a set of (tm_id, version)
    that already have both threatmodel.json, has the main DFD, and at least one other PNG in img/.
    """
    s3 = aws_client("s3")
    ct: str | None = None
    root = f"{dataset_prefix.rstrip('/')}/"
    status: Dict[tuple[str, str], Dict[str, Any]] = {}
    while True:
        kwargs: Dict[str, Any] = {"Bucket": bucket, "Prefix": root}
        if ct:
            kwargs["ContinuationToken"] = ct
        resp = s3.list_objects_v2(**kwargs)
        for o in resp.get("Contents", []):
            key = (o.get("Key") or "")
            if not key or key.endswith("/"):
                continue
            if not key.startswith(root):
                continue
            rest = key[len(root):]
            parts = rest.split("/", 2)
            if len(parts) < 3:
                continue
            tm_id, ver, tail = parts[0], parts[1], parts[2]
            k = (tm_id, ver)
            entry = status.setdefault(k, {"has_json": False, "pngs": 0, "has_main_dfd": False})
            if tail == "threatmodel.json":
                entry["has_json"] = True
            elif tail.startswith(f"img/") and tail.lower().endswith(("_dfd.png", "-dfd.png")):
                entry["has_main_dfd"] = True
            elif tail.startswith("img/") and tail.lower().endswith(".png") and not tail.lower().endswith(("_dfd.png", "-dfd.png")):
                entry["pngs"] += 1
        if not resp.get("IsTruncated"):
            break
        ct = resp.get("NextContinuationToken")
    done: set[tuple[str, str]] = set()
    for k, v in status.items():
        if v.get("has_json") and v.get("has_main_dfd") and (v.get("pngs", 0) > 0):
            done.add(k)
    return done


def update_manifest_entry(
    s3_bucket: str,
    dataset_prefix: str,
    threatmodels_state: Dict[str, Any],
    tm_id: str,
    ver: str,
) -> bool:
    s3 = aws_client("s3")
    prefix = f"{dataset_prefix.rstrip('/')}/{tm_id}/{ver}/"

    # Inventory S3 objects for this TM/version
    objs: List[Dict[str, Any]] = []
    continuation_token = None
    while True:
        kwargs = {"Bucket": s3_bucket, "Prefix": prefix}
        if continuation_token:
            kwargs["ContinuationToken"] = continuation_token
        resp = s3.list_objects_v2(**kwargs)
        objs.extend(resp.get("Contents", []))
        if resp.get("IsTruncated"):
            continuation_token = resp.get("NextContinuationToken")
        else:
            break

    json_meta = None
    images_meta: List[Dict[str, Any]] = []
    for o in objs:
        key = o.get("Key", "")
        if not key or key.endswith("/"):
            continue
        size = int(o.get("Size", 0))
        lm = o.get("LastModified")
        lm_iso = lm.astimezone(timezone.utc).isoformat() if lm else None
        if key == f"{prefix}threatmodel.json":
            json_meta = {"s3_key": key, "size": size, "last_modified": lm_iso}
        elif key.startswith(f"{prefix}img/") and key.lower().endswith(".png"):
            images_meta.append({"s3_key": key, "size": size, "last_modified": lm_iso})

    # Snapshot previous state for change detection
    prev_tm_entry = threatmodels_state.get(tm_id, {})
    prev_versions = (prev_tm_entry.get("versions") or {})
    prev_ver_entry = deepcopy(prev_versions.get(ver))
    prev_latest = prev_tm_entry.get("latest")
    prev_title = prev_tm_entry.get("title")

    # If there is nothing new to record and no previous XML to preserve, skip touching the manifest
    if not json_meta and not images_meta and not (prev_ver_entry and prev_ver_entry.get("xml")):
        return False

    # Build new version entry (preserve any existing XML list)
    tm_entry = threatmodels_state.setdefault(tm_id, {})
    vers_entry = tm_entry.setdefault("versions", {})
    ver_entry = {
        "json": json_meta,
        "images": sorted(images_meta, key=lambda x: x["s3_key"]),
        "xml": sorted((prev_ver_entry or {}).get("xml", []), key=lambda x: x.get("s3_key", "")),
    }
    changed = (prev_ver_entry != ver_entry)
    vers_entry[ver] = ver_entry

    # Recompute latest and title for this tm
    version_keys = list(vers_entry.keys())

    def _key_fn(v: str) -> tuple[int, int | str]:
        try:
            return (0, int(v))
        except Exception:
            return (1, v)

    version_keys_sorted = sorted(version_keys, key=_key_fn)
    latest = None
    if version_keys_sorted:
        numeric = [int(v) for v in version_keys_sorted if str(v).isdigit()]
        latest = str(max(numeric)) if numeric else version_keys_sorted[-1]
        if latest != prev_latest:
            changed = True
        tm_entry["latest"] = latest
        # Try to set title from latest json in S3
        latest_meta = vers_entry.get(latest, {})
        _json_meta = (latest_meta or {}).get("json") or {}
        _json_key = _json_meta.get("s3_key")
        if _json_key:
            try:
                _latest_json = s3_read_json(s3_bucket, _json_key)
                _meta = (_latest_json or {}).get("metadata") or {}
                _title = _meta.get("service_name") or _meta.get("service")
                if _title and _title != prev_title:
                    tm_entry["title"] = _title
                    changed = True
            except Exception:
                pass

    return changed


def normalise_tm_list(api_payload: Any) -> List[Tuple[str, List[str]]]:
    # Supports either:
    # - {"threatmodels": [{"threatmodel_id": "...", "versions": [...]}, ...]}
    # - [{"threatmodel_id": "...", "versions": [...]}, ...]
    if isinstance(api_payload, dict) and "threatmodels" in api_payload:
        items = api_payload.get("threatmodels") or []
    else:
        items = api_payload or []
    out: List[Tuple[str, List[str]]] = []
    if not isinstance(items, list):
        return out
    for it in items:
        if not isinstance(it, dict):
            continue
        tm_id = str(it.get("threatmodel_id") or it.get("id") or "").strip()
        versions = [str(v) for v in (it.get("versions") or [])]
        if tm_id and versions:
            out.append((tm_id, versions))
    return out


def _fetch_tm_version_cached(api_base: str, tm_id: str, version_id: str) -> Dict[str, Any]:
    logging.info(f'Fetching {tm_id} version {version_id}')
    url = f"{api_base}/threatmodels/{urllib.parse.quote(tm_id, safe='')}/versions/{urllib.parse.quote(version_id, safe='')}"
    result = execute_get(url)
    body = result.get("body")
    if not isinstance(body, dict):
        raise RuntimeError(f"Unexpected payload for {tm_id}/{version_id}")
    return body


def fetch_tm_version(api_base: str, tm_id: str, version_id: str) -> Dict[str, Any]:
    # Return a defensive copy so callers cannot mutate the cached object.
    return deepcopy(_fetch_tm_version_cached(api_base, tm_id, version_id))


@dataclass(frozen=True)
class Config:
    dataset_bucket: str
    dataset_prefix: str
    search_bucket: str
    search_prefix: str
    api_base: str
    metadata_key: str
    tm_ids_filter: set[str]
    force_rerender: bool


def load_config() -> Config:
    dataset_bucket = env_str("DATASET_BUCKET", required=True)
    dataset_prefix = env_str("DATASET_PREFIX", required=True)
    search_bucket = env_str("SEARCH_BUCKET", required=True)
    search_prefix = env_str("SEARCH_PREFIX", required=True)

    api_base = env_str("API_BASE_URL", default="https://api.internal.trustoncloud.com/apikey").rstrip("/")
    metadata_key = env_str("METADATA_KEY", default="_dfd_sync/manifest.json")

    tm_ids_raw = os.environ.get("TM_IDS", "")
    tm_ids_raw = ("" if tm_ids_raw is None else str(tm_ids_raw)).strip().strip('"').strip("'")
    if tm_ids_raw in ("=", "''", '""'):
        tm_ids_raw = ""
    tm_ids_filter: set[str] = {x.strip() for x in tm_ids_raw.split(",") if x.strip()}

    force_rerender = os.environ.get("RERENDER_EXISTING", "").strip().lower() in ("1", "true", "yes", "y", "on")

    return Config(
        dataset_bucket=dataset_bucket,
        dataset_prefix=dataset_prefix,
        search_bucket=search_bucket,
        search_prefix=search_prefix,
        api_base=api_base,
        metadata_key=metadata_key,
        tm_ids_filter=tm_ids_filter,
        force_rerender=force_rerender,
    )


def prepare_drawio_environment() -> None:
    os.environ.setdefault("HOME", "/tmp/drawio-home")
    os.environ.setdefault("XDG_CACHE_HOME", "/tmp/drawio-cache")
    os.environ.setdefault("XDG_CONFIG_HOME", "/tmp/drawio-config")
    for _d in (os.environ["HOME"], os.environ["XDG_CACHE_HOME"], os.environ["XDG_CONFIG_HOME"]):
        Path(_d).mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["fc-cache", "-f"], check=False, timeout=30)
    except Exception as _e:
        logger.debug("fc-cache warm-up skipped/failed: %s", _e)


def fetch_threatmodels_list(api_base: str, tm_ids_filter: set[str]) -> List[Tuple[str, List[str]]]:
    list_url = f"{api_base}/threatmodels"
    list_resp = execute_get(list_url)
    tm_list = normalise_tm_list(list_resp.get("body"))
    logger.info("Fetched %d threatmodels from API", len(tm_list))

    if tm_ids_filter:
        before = len(tm_list)
        tm_list = [(tm_id, versions) for tm_id, versions in tm_list if tm_id in tm_ids_filter]
        logger.info("TM_IDS provided: restricting to %d specified threatmodels (from %d)", len(tm_list), before)

    return tm_list


def process_single_version(
    config: Config,
    tm_id: str,
    ver: str,
    tmp_path: Path,
    threatmodels_state: Dict[str, Any],
    existing_complete: set[tuple[str, str]],
) -> bool:
    if (tm_id, ver) in existing_complete and not config.force_rerender:
        logger.info("Skipping %s version %s already in S3.", tm_id, ver)
        # Backfill manifest entries even when skipping rendering/upload; only trigger write when changed
        try:
            changed = update_manifest_entry(
                config.dataset_bucket, config.dataset_prefix, threatmodels_state, tm_id, ver
            )
        except Exception as e:
            logger.warning("Failed to backfill manifest for skipped %s/%s: %s", tm_id, ver, e)
            return False
        return changed

    logger.info("Processing %s/%s ...", tm_id, ver)
    try:
        tm_json = fetch_tm_version(config.api_base, tm_id, ver)
    except Exception as e:
        logger.warning("Skipping %s/%s: failed to fetch version: %s", tm_id, ver, e)
        return False

    try:
        dfd = tm_json.get("dfd") or {}
        b64 = str(dfd.get("body") or "")
        if not b64:
            logger.info("Skipping %s/%s: empty dfd.body", tm_id, ver)
            return False

        # Prepare a clean work area for this item
        work = tmp_path / f"tm_{tm_id}_{ver}"
        work.mkdir(parents=True, exist_ok=True)

        # Build draw.io XML
        src_xml = work / f"{tm_id}_{ver}_DFD.xml"
        src_xml.write_text(base64.b64decode(b64).decode("utf-8"), encoding="utf-8")

        # Generate variants and render PNGs
        out_dir = work / "rendered"
        pngs, _xmls = generate_variants_and_render(src_xml, out_dir)

        # Upload PNGs
        s3_prefix = f"{config.dataset_prefix}/{tm_id}/{ver}"
        upload_images(config.dataset_bucket, s3_prefix, pngs)

        # Upload ThreatModel JSON after images
        json_key = f"{config.dataset_prefix}/{tm_id}/{ver}/threatmodel.json"
        s3_write_json(config.dataset_bucket, json_key, tm_json)
        logger.info("Uploaded JSON to s3://%s/%s", config.dataset_bucket, json_key)

        # Track JSON hash and persist in state
        tm_json_sha = hashlib.sha256(
            json.dumps(tm_json, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        tm_entry = threatmodels_state.setdefault(tm_id, {})
        vers_entry = tm_entry.setdefault("versions", {})
        ver_entry = vers_entry.setdefault(ver, {})
        ver_entry["tm_json_sha256"] = tm_json_sha

        # Update manifest entry metadata for this version
        update_manifest_entry(config.dataset_bucket, config.dataset_prefix, threatmodels_state, tm_id, ver)

        return True
    except DrawioExportHardFailure as e:
        logger.error("Hard fail: draw.io export failed for %s/%s after all strategies: %s", tm_id, ver, e)
        raise
    except Exception as e:
        logger.error("Failed to render/upload %s/%s: %s", tm_id, ver, e)
        return False


def main() -> int:
    try:
        cfg = load_config()

        # 1) List threatmodels/versions
        tm_list = fetch_threatmodels_list(cfg.api_base, cfg.tm_ids_filter)

        # 2) Load previous state
        manifest: Dict[str, Any] = s3_read_json(cfg.dataset_bucket, cfg.metadata_key)
        threatmodels_state: Dict[str, Any] = dict(manifest.get("threatmodels") or {})

        existing_complete = s3_scan_existing_versions(cfg.dataset_bucket, cfg.dataset_prefix)

        # 3) Prepare draw.io environment
        prepare_drawio_environment()

        # 4) Start a single Xvfb for the entire run
        xvfb_proc = start_xvfb()
        time.sleep(0.5)
        try:
            # 5) Process and upload per version in a single pass
            for tm_id, versions in tm_list:
                for ver in versions:
                    with TemporaryDirectory() as tmpdir:
                        tmp_path = Path(tmpdir)

                        processed = process_single_version(
                            cfg, tm_id, ver, tmp_path, threatmodels_state, existing_complete
                        )
                        if not processed:
                            continue

                        # Write manifest after each successful version (iterative safety)
                        manifest["threatmodels"] = threatmodels_state
                        if "items" in manifest:
                            try:
                                del manifest["items"]
                            except Exception:
                                pass
                        manifest["generated_at"] = datetime.now(timezone.utc).isoformat()
                        s3_write_json(cfg.dataset_bucket, cfg.metadata_key, manifest)
                        logger.info(
                            "Updated manifest for %s/%s at s3://%s/%s",
                            tm_id,
                            ver,
                            cfg.dataset_bucket,
                            cfg.metadata_key,
                        ) 
        finally:
            stop_xvfb(xvfb_proc)
        # Write manifest at the end as safety
        manifest["threatmodels"] = threatmodels_state
        if "items" in manifest:
            try:
                del manifest["items"]
            except Exception:
                pass
        manifest["generated_at"] = datetime.now(timezone.utc).isoformat()
        s3_write_json(cfg.dataset_bucket, cfg.metadata_key, manifest)

        # 6) Build and upload the search dataset (latest version per TM)
        try:
            build_and_upload_search_dataset(
                search_bucket=cfg.search_bucket,
                search_prefix=cfg.search_prefix,
                api_base=cfg.api_base,
                tm_ids_filter=cfg.tm_ids_filter,
                fetch_tm_version_func=fetch_tm_version,
                fetch_threatmodels_list_func=fetch_threatmodels_list,
            )
        except Exception as e:
            logger.warning("Search dataset generation failed: %s", e)

        logger.info("Done.")
        return 0
    except Exception as e:
        logger.error("FATAL: %s", e)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
