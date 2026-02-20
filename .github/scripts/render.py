from __future__ import annotations

import base64
import json
import logging
import os
import re
import shutil
import subprocess
import time
import urllib.parse
import zlib
from pathlib import Path
from subprocess import Popen
from typing import Any, List, Tuple

from bs4 import BeautifulSoup as BS4

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
logger = logging.getLogger("render")
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


def find_single_root_json(repo_root: Path) -> Path:
    files = sorted(repo_root.glob("*.json"))
    if len(files) == 0:
        raise RuntimeError("No root JSON file found in repository root")
    if len(files) > 1:
        raise RuntimeError(
            f"Expected exactly one root JSON file, found {len(files)}: {', '.join([p.name for p in files])}"
        )
    return files[0]


def load_root_threatmodel_json(json_path: Path) -> dict[str, Any]:
    tm_json = json.loads(json_path.read_text(encoding="utf-8"))

    if not isinstance(tm_json, dict):
        raise RuntimeError(f"Root JSON must be an object, got {type(tm_json).__name__}")

    metadata = tm_json.get("metadata")
    if not isinstance(metadata, dict):
        raise RuntimeError("Missing required field: metadata")

    if not metadata.get("provider"):
        raise RuntimeError("Missing required field: metadata.provider")
    if not metadata.get("service"):
        raise RuntimeError("Missing required field: metadata.service")

    dfd = tm_json.get("dfd")
    if not isinstance(dfd, dict):
        raise RuntimeError("Missing required field: dfd")

    body = dfd.get("body")
    if not body:
        raise RuntimeError("Missing required field: dfd.body")

    return tm_json


def build_root_xml_filename(tm_json: dict[str, Any]) -> str:
    provider = str(tm_json["metadata"]["provider"]).upper()
    service = str(tm_json["metadata"]["service"]).upper()
    return f"{provider}_{service}_DFD.xml"


def clean_img_dir(repo_root: Path) -> Path:
    img_dir = repo_root / "img"
    img_dir.mkdir(parents=True, exist_ok=True)
    for p in img_dir.iterdir():
        if p.is_file():
            p.unlink()
    return img_dir


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
    proc = Popen(
        ["Xvfb", ":99", "-screen", "0", "3840x2160x24", "-nolisten", "tcp", "-ac"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
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
    logger.debug("Attempting draw.io export: input=%s output=%s", inp, output_path)

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
    logger.debug("drawio export succeeded: %s (size=%d bytes)", output_path, size)

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

        opacity_tool = Path(__file__).with_name("threat_opacity_xml_creator.py")
        if not opacity_tool.exists():
            raise FileNotFoundError(f"Opacity tool not found: {opacity_tool}")

        # Create FC and Threat variants with validation
        run_cmd(
            [
                "python",
                str(opacity_tool),
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
            logger.debug("Will render %d PNG(s) from %s", len(xml_list), sub)
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


# NOTE: AWS/S3 upload helpers were removed as the workflow is now local-only.


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


def main() -> int:
    try:
        repo_root = Path(__file__).resolve().parents[2]

        json_path = find_single_root_json(repo_root)
        tm_json = load_root_threatmodel_json(json_path)

        img_dir = clean_img_dir(repo_root)

        b64 = str(tm_json["dfd"]["body"] or "")
        xml_text = base64.b64decode(b64).decode("utf-8")
        xml_out_path = repo_root / build_root_xml_filename(tm_json)
        xml_out_path.write_text(xml_text, encoding="utf-8")
        logger.info("Wrote root DFD XML: %s", xml_out_path)

        prepare_drawio_environment()

        xvfb_proc = start_xvfb()
        time.sleep(0.5)
        try:
            generate_variants_and_render(src_xml=xml_out_path, out_dir=img_dir, manage_xvfb=False)
        finally:
            stop_xvfb(xvfb_proc)

        logger.info("Done.")
        return 0
    except Exception as e:
        logger.error("FATAL: %s", e)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
