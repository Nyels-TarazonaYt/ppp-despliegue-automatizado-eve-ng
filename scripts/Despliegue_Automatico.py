#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import select
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

# -------------------------
# Paths del proyecto
# -------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
TOPO_DIR = PROJECT_ROOT / "topologies"
EVID_LOG_DIR = PROJECT_ROOT / "Evidencias" / "logs"

# -------------------------
# Defaults
# -------------------------
DEFAULT_BASE = os.getenv("EVE_BASE", "") or "http://192.168.10.132"
DEFAULT_USER = os.getenv("EVE_USER", "admin")
DEFAULT_PASS = os.getenv("EVE_PASS", "eve")
DEFAULT_BRIDGE_VISIBILITY = int(os.getenv("EVE_BRIDGE_VISIBILITY", "1"))

TOPO_FILES = {
    "basico": TOPO_DIR / "basico.json",
    "intermedio": TOPO_DIR / "intermedio.json",
    "avanzado": TOPO_DIR / "avanzado.json",
}

def q(s: str) -> str:
    return urllib.parse.quote(s, safe="")

def clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, v))

def load_dotenv_safely(dotenv_path: Path) -> None:
    if not dotenv_path.exists():
        return
    try:
        from dotenv import load_dotenv  # type: ignore
        load_dotenv(dotenv_path)
        return
    except Exception:
        for line in dotenv_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def make_logger(dst_labfile: str, nivel: str, enabled: bool = True):
    if not enabled:
        def _log(msg: str):
            print(msg)
        return _log, None

    EVID_LOG_DIR.mkdir(parents=True, exist_ok=True)
    safe_lab = re.sub(r"[^a-zA-Z0-9_.-]+", "_", dst_labfile)
    log_path = EVID_LOG_DIR / f"{now_stamp()}_{nivel}_{safe_lab}.log"

    def _log(msg: str):
        print(msg)
        with log_path.open("a", encoding="utf-8") as f:
            f.write(msg + "\n")

    return _log, log_path

# -------------------------
# Validación JSON
# -------------------------
def validate_topology(topo: Dict[str, Any]) -> List[str]:
    errors: List[str] = []

    if not isinstance(topo, dict):
        return ["El JSON raíz debe ser un objeto."]

    if "nodes" not in topo or not isinstance(topo["nodes"], list) or not topo["nodes"]:
        errors.append("Falta 'nodes' (lista no vacía).")

    if "links" not in topo or not isinstance(topo["links"], list):
        errors.append("Falta 'links' (lista).")

    names = set()
    for i, n in enumerate(topo.get("nodes", []), start=1):
        if not isinstance(n, dict):
            errors.append(f"nodes[{i}] debe ser un objeto.")
            continue
        for k in ("name", "template", "type"):
            if not n.get(k):
                errors.append(f"nodes[{i}] falta '{k}'.")
        if "left" not in n or "top" not in n:
            errors.append(f"nodes[{i}] debe incluir 'left' y 'top'.")
        name = n.get("name")
        if name:
            if name in names:
                errors.append(f"Nombre de nodo duplicado: '{name}'.")
            names.add(name)

    for i, lk in enumerate(topo.get("links", []), start=1):
        if not isinstance(lk, dict) or "a" not in lk or "b" not in lk:
            errors.append(f"links[{i}] debe tener 'a' y 'b'.")
            continue
        for side in ("a", "b"):
            s = lk.get(side)
            if not isinstance(s, dict):
                errors.append(f"links[{i}].{side} debe ser un objeto.")
                continue
            if not s.get("node"):
                errors.append(f"links[{i}].{side} falta 'node'.")
            if not s.get("iface"):
                errors.append(f"links[{i}].{side} falta 'iface'.")

    return errors

def precheck_topology(topo: Dict[str, Any]) -> List[str]:
    warns: List[str] = []
    seen = set()

    for lk in topo.get("links", []):
        if not isinstance(lk, dict):
            continue
        a = lk.get("a", {})
        b = lk.get("b", {})
        key = tuple(sorted([(a.get("node"), a.get("iface")), (b.get("node"), b.get("iface"))]))
        if key in seen:
            warns.append(f"Conexión duplicada detectada: {key}")
        seen.add(key)

    return warns

# -------------------------
# API EVE-NG
# -------------------------
class EveAPI:
    def __init__(self, base: str, user: str, password: str, logger):
        self.base = base.rstrip("/")
        self.user = user
        self.password = password
        self.s = requests.Session()
        self.log = logger

    def _eve_host_from_base(self) -> str:
        u = urllib.parse.urlparse(self.base)
        return u.hostname or "127.0.0.1"

    def _cache_params(self) -> Dict[str, Any]:
        return {"_": int(time.time() * 1000)}

    def login(self):
        payload = {"username": self.user, "password": self.password, "html5": "0"}
        r = self.s.post(
            f"{self.base}/api/auth/login",
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=20,
        )
        if not r.ok:
            raise RuntimeError(f"Error al iniciar sesión en EVE-NG: {r.status_code} {r.text}")
        self.log("✅ Login exitoso")

    def folders(self):
        r = self.s.get(f"{self.base}/api/folders/", timeout=20, params=self._cache_params())
        if not r.ok:
            raise RuntimeError(f"Error al obtener carpetas/laboratorios: {r.status_code} {r.text}")
        return r.json()["data"]

    def lab_exists(self, labfile: str) -> bool:
        data = self.folders()
        return any(l.get("file") == labfile for l in data.get("labs", []))

    def delete_lab(self, labfile: str):
        r = self.s.delete(f"{self.base}/api/labs/{q(labfile)}", timeout=20, params=self._cache_params())
        if not r.ok:
            raise RuntimeError(f"No se pudo eliminar el laboratorio: {r.status_code} {r.text}")
        self.log(f"🗑️ Laboratorio eliminado: {labfile}")

    def create_lab(self, labfile: str, desc: str):
        name_no_ext = labfile[:-4] if labfile.endswith(".unl") else labfile
        payload = {
            "path": "/",
            "name": name_no_ext,
            "version": "1",
            "author": "FIIS-UNAS",
            "description": desc,
            "body": "PPP - despliegue automatizado (IaC)",
        }
        r = self.s.post(
            f"{self.base}/api/labs",
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=20,
        )
        if not r.ok:
            raise RuntimeError(f"Error al crear el laboratorio: {r.status_code} {r.text}")
        self.log(f"✅ Laboratorio creado: {name_no_ext}.unl")

    def add_node(self, labfile: str, node: dict) -> int:
        payload = {
            "template": node["template"],
            "type": node["type"],
            "name": node["name"],
            "left": int(node.get("left", 100)),
            "top": int(node.get("top", 100)),
            "ram": node.get("ram"),
            "cpu": node.get("cpu"),
            "ethernet": node.get("ethernet"),
            "console": node.get("console", "telnet"),
            "image": node.get("image", ""),
            "icon": node.get("icon"),
            "delay": node.get("delay", 0),
            "idlepc": node.get("idlepc"),
            "nvram": node.get("nvram"),
            "serial": node.get("serial"),
        }

        for i in range(0, 7):
            k = f"slot{i}"
            if node.get(k):
                payload[k] = node[k]

        payload = {k: v for k, v in payload.items() if v is not None}

        r = self.s.post(
            f"{self.base}/api/labs/{q(labfile)}/nodes",
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=20,
        )
        if not r.ok:
            raise RuntimeError(f"Error al crear el nodo {node['name']}: {r.status_code} {r.text}")
        return int(r.json()["data"]["id"])

    def create_bridge(self, labfile: str, name: str, left: int, top: int, visibility: int) -> int:
        payload = {
            "type": "bridge",
            "name": name,
            "left": int(left),
            "top": int(top),
            "visibility": int(visibility),
        }
        r = self.s.post(
            f"{self.base}/api/labs/{q(labfile)}/networks",
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=20,
        )
        if not r.ok:
            raise RuntimeError(f"Error al crear el bridge '{name}': {r.status_code} {r.text}")
        net_id = int(r.json()["data"]["id"])
        time.sleep(0.15)
        return net_id

    def get_network(self, labfile: str, net_id: int) -> Dict[str, Any]:
        r = self.s.get(
            f"{self.base}/api/labs/{q(labfile)}/networks/{net_id}",
            timeout=20,
            params=self._cache_params(),
        )
        if not r.ok:
            raise RuntimeError(f"Error al consultar la red {net_id}: {r.status_code} {r.text}")
        return r.json()["data"]

    def set_network_visibility(self, labfile: str, net_id: int, visibility: int):
        data = self.get_network(labfile, net_id)

        payload = {
            "name": data.get("name", f"BR_{net_id}"),
            "type": data.get("type", "bridge"),
            "left": int(data.get("left", 100)),
            "top": int(data.get("top", 100)),
            "visibility": int(visibility),
        }

        r = self.s.put(
            f"{self.base}/api/labs/{q(labfile)}/networks/{net_id}",
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=20,
        )
        if not r.ok:
            raise RuntimeError(
                f"No se pudo cambiar la visibilidad del bridge {net_id}: {r.status_code} {r.text}"
            )

    def list_nodes(self, labfile: str) -> Dict[str, Any]:
        r = self.s.get(f"{self.base}/api/labs/{q(labfile)}/nodes", timeout=20, params=self._cache_params())
        if not r.ok:
            raise RuntimeError(f"Error al listar nodos: {r.status_code} {r.text}")
        return r.json()["data"]

    def get_node(self, labfile: str, node_id: int) -> Dict[str, Any]:
        r = self.s.get(
            f"{self.base}/api/labs/{q(labfile)}/nodes/{node_id}",
            timeout=20,
            params=self._cache_params(),
        )
        if not r.ok:
            raise RuntimeError(f"Error al consultar el nodo {node_id}: {r.status_code} {r.text}")
        return r.json()["data"]

    def start_node(self, labfile: str, node_id: int) -> None:
        r = self.s.get(
            f"{self.base}/api/labs/{q(labfile)}/nodes/{node_id}/start",
            timeout=30,
            params=self._cache_params(),
        )
        if not r.ok:
            raise RuntimeError(f"Error al iniciar el nodo {node_id}: {r.status_code} {r.text}")

    def start_all_nodes(self, labfile: str) -> Dict[str, Any]:
        r = self.s.get(
            f"{self.base}/api/labs/{q(labfile)}/nodes/start",
            timeout=90,
            params=self._cache_params(),
        )
        try:
            return r.json()
        except Exception:
            return {"code": r.status_code, "message": r.text}

    def list_interfaces(self, labfile: str, node_id: int) -> dict:
        r = self.s.get(
            f"{self.base}/api/labs/{q(labfile)}/nodes/{node_id}/interfaces",
            timeout=20,
            params=self._cache_params(),
        )
        if not r.ok:
            raise RuntimeError(f"Error al listar interfaces del nodo {node_id}: {r.status_code} {r.text}")
        return r.json()["data"]

    def get_iface_key(self, labfile: str, node_id: int, iface_name: str) -> str:
        data = self.list_interfaces(labfile, node_id)
        eth = data.get("ethernet")
        if eth is None:
            raise ValueError(f"El nodo {node_id} no tiene interfaces ethernet disponibles.")

        target = (iface_name or "").lower()

        def try_match(name_to_find: str) -> Optional[str]:
            if isinstance(eth, dict):
                for key, item in eth.items():
                    if (item.get("name") or "").lower() == name_to_find:
                        return str(key)
            elif isinstance(eth, list):
                for idx, item in enumerate(eth):
                    if isinstance(item, dict) and (item.get("name") or "").lower() == name_to_find:
                        return str(idx)
            return None

        k = try_match(target)
        if k is not None:
            return k

        fallbacks: List[str] = []
        m = re.match(r"^(fa)(\d+)/(\d+)$", target)
        if m:
            base, _, port = m.groups()
            for idx in range(0, 4):
                fallbacks.append(f"{base}{idx}/{port}")

        m = re.match(r"^(gi)(\d+)/(\d+)$", target)
        if m:
            base, _, port = m.groups()
            for idx in range(0, 4):
                fallbacks.append(f"{base}{idx}/{port}")

        m = re.match(r"^(e)(\d+)/(\d+)$", target)
        if m:
            base, _, port = m.groups()
            for idx in range(0, 8):
                fallbacks.append(f"{base}{idx}/{port}")

        for fb in fallbacks:
            k = try_match(fb)
            if k is not None:
                return k

        if isinstance(eth, dict):
            available = [v.get("name") for v in eth.values()]
        else:
            available = [x.get("name") if isinstance(x, dict) else str(x) for x in eth]

        raise ValueError(
            f"No se encontró la interfaz '{iface_name}' en el nodo {node_id}. Interfaces disponibles: {available}"
        )

    def connect_iface(self, labfile: str, node_id: int, iface_key: str, net_id: int):
        payload = {str(iface_key): int(net_id)}
        last = None
        for _ in range(12):
            r = self.s.put(
                f"{self.base}/api/labs/{q(labfile)}/nodes/{node_id}/interfaces",
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload),
                timeout=20,
            )
            if r.ok:
                return True
            last = (r.status_code, r.text)
            time.sleep(0.25)
        raise RuntimeError(f"No se pudo conectar la interfaz del nodo {node_id}. Último error: {last}")

# -------------------------
# Bridge XY
# -------------------------
def compute_bridge_xy(a_pos: Tuple[int, int], b_pos: Tuple[int, int], i: int, max_left: int, max_top: int) -> Tuple[int, int]:
    ax, ay = a_pos
    bx, by = b_pos
    mx = int((ax + bx) / 2)
    my = int((ay + by) / 2)

    dx = bx - ax
    dy = by - ay

    length = (dx * dx + dy * dy) ** 0.5
    if length == 0:
        px, py = 1.0, 0.0
    else:
        px, py = -dy / length, dx / length

    dist = 18 + (i % 5) * 6
    sign = -1 if (i % 2 == 0) else 1

    cx = int(mx + sign * px * dist)
    cy = int(my + sign * py * dist)

    return clamp(cx, 0, max_left + 200), clamp(cy, 0, max_top + 200)

# -------------------------
# Telnet sin telnetlib
# -------------------------
IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240

def _telnet_consume_iac(data: bytes, sock: socket.socket) -> None:
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b != IAC:
            i += 1
            continue
        if i + 1 >= n:
            break
        if data[i + 1] == IAC:
            i += 2
            continue
        if data[i + 1] == SB:
            i += 2
            while i < n:
                if data[i] == IAC and i + 1 < n and data[i + 1] == SE:
                    i += 2
                    break
                i += 1
            continue
        if data[i + 1] in (DO, DONT, WILL, WONT):
            if i + 2 >= n:
                break
            opt = data[i + 2]
            try:
                if data[i + 1] == DO:
                    sock.sendall(bytes([IAC, WONT, opt]))
                elif data[i + 1] == WILL:
                    sock.sendall(bytes([IAC, DONT, opt]))
            except Exception:
                pass
            i += 3
            continue
        i += 2

def _extract_telnet_host_port_from_url(api: EveAPI, url: str) -> Tuple[Optional[str], Optional[int]]:
    m = re.search(r"telnet://([^:]+):(\d+)", url or "")
    if not m:
        return None, None
    host = m.group(1)
    port = int(m.group(2))
    if host in ("127.0.0.1", "0.0.0.0", "localhost"):
        host = api._eve_host_from_base()
    return host, port

def _get_telnet_url_fallback(api: EveAPI, labfile: str, node_id: int) -> Optional[str]:
    try:
        ni = api.get_node(labfile, node_id)
        u = ni.get("url")
        if isinstance(u, str) and u.startswith("telnet://"):
            return u
    except Exception:
        pass

    try:
        nodes = api.list_nodes(labfile)
        nd = nodes.get(str(node_id)) or nodes.get(int(node_id))
        if isinstance(nd, dict):
            u = nd.get("url")
            if isinstance(u, str) and u.startswith("telnet://"):
                return u
    except Exception:
        pass

    return None

def telnet_send_lines(host: str, port: int, lines: List[str], wait_seconds: int, log, smart: bool = True) -> None:
    log(f"🖧 Conectando a consola: {host}:{port} (espera {wait_seconds}s)")
    deadline = time.time() + max(5, int(wait_seconds))

    try:
        sock = socket.create_connection((host, int(port)), timeout=20)
        sock.setblocking(False)

        buf = b""
        last_enter = 0.0

        while time.time() < deadline:
            if smart and (time.time() - last_enter) > 1.2:
                try:
                    sock.sendall(b"\r\n")
                except Exception:
                    pass
                last_enter = time.time()

            r, _, _ = select.select([sock], [], [], 0.25)
            if not r:
                continue

            chunk = sock.recv(4096)
            if not chunk:
                break

            _telnet_consume_iac(chunk, sock)
            buf += chunk
            low = buf.lower()

            if b"press return to get started" in low:
                try:
                    sock.sendall(b"\r\n")
                except Exception:
                    pass
                buf = b""
                continue

            if b"initial configuration dialog" in low or b"[yes/no]" in low:
                try:
                    sock.sendall(b"no\r\n")
                except Exception:
                    pass
                buf = b""
                continue

            if smart and re.search(br"[\r\n][^\r\n]*[>#]\s*$", buf):
                break

        for line in lines:
            cmd = (line or "") + "\r\n"
            sock.sendall(cmd.encode("utf-8", errors="ignore"))
            time.sleep(0.9)

            t_end = time.time() + 0.35
            while time.time() < t_end:
                r, _, _ = select.select([sock], [], [], 0.05)
                if not r:
                    break
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    _telnet_consume_iac(chunk, sock)
                except Exception:
                    break

        sock.close()
        log("✅ Configuración aplicada correctamente")
    except Exception as e:
        log(f"❌ Error al aplicar la configuración por consola: {e}")

# -------------------------
# Start y bootstrap
# -------------------------
def _node_is_running(node_info: Dict[str, Any]) -> bool:
    try:
        return int(node_info.get("status", 0)) != 0
    except Exception:
        return False

def _wait_running(api: EveAPI, labfile: str, node_id: int, timeout_s: int = 90) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            info = api.get_node(labfile, node_id)
            if _node_is_running(info):
                return True
        except Exception:
            pass
        time.sleep(2)
    return False

def start_nodes_if_needed(api: EveAPI, labfile: str, id_by_name: Dict[str, int], topo: Dict[str, Any]) -> None:
    api.log("▶️ Iniciando nodos...")

    try:
        api.start_all_nodes(labfile)
    except Exception as e:
        api.log(f"⚠️ Advertencia: no se pudo iniciar todos los nodos de una sola vez: {e}")

    for n in topo.get("nodes", []):
        name = n.get("name")
        if not name:
            continue
        node_id = id_by_name.get(name)
        if not node_id:
            continue

        ok = _wait_running(api, labfile, node_id, timeout_s=60)
        if ok:
            api.log(f"✅ Nodo iniciado: {name}")
            continue

        try:
            api.start_node(labfile, node_id)
        except Exception as e:
            api.log(f"❌ Error al iniciar el nodo {name}: {e}")
            continue

        ok2 = _wait_running(api, labfile, node_id, timeout_s=60)
        if ok2:
            api.log(f"✅ Nodo iniciado: {name}")
        else:
            api.log(f"❌ El nodo {name} sigue apagado. Revísalo manualmente en EVE-NG.")

def apply_bootstrap_all(api: EveAPI, labfile: str, topo: Dict[str, Any], id_by_name: Dict[str, int]) -> None:
    api.log("🧩 Aplicando configuraciones:")

    for n in topo.get("nodes", []):
        if not isinstance(n, dict):
            continue
        b = n.get("bootstrap")
        if not isinstance(b, dict):
            continue
        if (b.get("mode") or "console") != "console":
            api.log(f"⚠️ Modo de bootstrap no soportado para {n.get('name')}. Solo se admite modo console.")
            continue

        name = n.get("name")
        if not name:
            continue
        node_id = id_by_name.get(name)
        if not node_id:
            api.log(f"❌ No se encontró el identificador del nodo {name}")
            continue

        try:
            api.start_node(labfile, node_id)
        except Exception:
            pass

        wait_seconds = int(b.get("wait_seconds", 10))
        try:
            wait_seconds = max(wait_seconds, int(n.get("delay", 0)))
        except Exception:
            pass

        lines = b.get("lines", [])
        if not isinstance(lines, list) or not lines:
            api.log(f"⚠️ No hay líneas de configuración para {name}. Se omite.")
            continue

        telnet_url = None
        try:
            node_info = api.get_node(labfile, node_id)
            u = node_info.get("url")
            if isinstance(u, str) and u.startswith("telnet://"):
                telnet_url = u
        except Exception:
            pass

        if not telnet_url:
            telnet_url = _get_telnet_url_fallback(api, labfile, node_id)

        if not telnet_url:
            api.log(f"❌ Error: no se pudo obtener la consola telnet para {name}")
            continue

        host, port = _extract_telnet_host_port_from_url(api, telnet_url)
        if not host or not port:
            api.log(f"❌ Error: no se pudo interpretar la consola del nodo {name}")
            continue

        api.log(f"➡️ Configuración en: {name}")
        smart = (n.get("type") != "vpcs" and n.get("template") != "vpcs")
        telnet_send_lines(host, int(port), [str(x) for x in lines], wait_seconds, api.log, smart=smart)

# -------------------------
# Topología
# -------------------------
def load_topology(nivel: str) -> Dict[str, Any]:
    topo_path = TOPO_FILES[nivel]
    if not topo_path.exists():
        raise FileNotFoundError(f"No se encontró el archivo de topología: {topo_path}")
    with topo_path.open("r", encoding="utf-8") as f:
        return json.load(f)

# -------------------------
# Deploy principal
# -------------------------
def deploy(
    api: EveAPI,
    topo: Dict[str, Any],
    dst_labfile: str,
    force: bool,
    visibility: int,
    dry_run: bool,
    start_flag: bool,
    bootstrap_flag: bool,
):
    desc = topo.get("meta", {}).get("description", "Topología desplegada desde JSON (IaC)")

    if dry_run:
        api.log("🧪 Modo simulación activado: no se realizarán cambios en EVE-NG.")
        api.log(f"Laboratorio destino: {dst_labfile}")
        api.log(f"Descripción: {desc}")
        api.log(f"Cantidad de nodos: {len(topo.get('nodes', []))}")
        api.log(f"Cantidad de conexiones: {len(topo.get('links', []))}")
        api.log("--- Nodos ---")
        for n in topo.get("nodes", []):
            api.log(f"- {n.get('name')} ({n.get('template')}/{n.get('type')}) posición=({n.get('left')},{n.get('top')})")
        api.log("--- Conexiones ---")
        for lk in topo.get("links", []):
            a = lk.get("a", {})
            b = lk.get("b", {})
            api.log(f"- {a.get('node')}:{a.get('iface')} <-> {b.get('node')}:{b.get('iface')}")
        return

    api.login()

    if force and api.lab_exists(dst_labfile):
        api.delete_lab(dst_labfile)

    api.create_lab(dst_labfile, desc)

    id_by_name: Dict[str, int] = {}
    pos_by_name: Dict[str, Tuple[int, int]] = {}

    max_left = 0
    max_top = 0

    for n in topo["nodes"]:
        new_id = api.add_node(dst_labfile, n)
        id_by_name[n["name"]] = new_id

        left = int(n.get("left", 100))
        top = int(n.get("top", 100))
        pos_by_name[n["name"]] = (left, top)

        max_left = max(max_left, left)
        max_top = max(max_top, top)

        api.log(f"✅ Nodo creado: {n['name']}")

    for i, link in enumerate(topo.get("links", []), start=1):
        a = link["a"]
        b = link["b"]

        a_name = a["node"]
        b_name = b["node"]

        a_id = id_by_name[a_name]
        b_id = id_by_name[b_name]

        br_left, br_top = compute_bridge_xy(pos_by_name[a_name], pos_by_name[b_name], i, max_left, max_top)

        net_id = api.create_bridge(dst_labfile, f"BR_{i}", br_left, br_top, visibility)

        a_key = api.get_iface_key(dst_labfile, a_id, a["iface"])
        b_key = api.get_iface_key(dst_labfile, b_id, b["iface"])

        api.connect_iface(dst_labfile, a_id, a_key, net_id)
        api.connect_iface(dst_labfile, b_id, b_key, net_id)

        try:
            api.set_network_visibility(dst_labfile, net_id, 0)
            api.log(f"🔗 Conexión exitosa: {a_name}:{a['iface']} <-> {b_name}:{b['iface']}")
        except Exception as e:
            api.log(
                f"⚠️ La conexión se realizó entre {a_name}:{a['iface']} y {b_name}:{b['iface']}, "
                f"pero no se pudo ocultar el bridge: {e}"
            )

    api.log("🎉 Topología creada exitosamente")

    if start_flag:
        start_nodes_if_needed(api, dst_labfile, id_by_name, topo)

    if bootstrap_flag:
        apply_bootstrap_all(api, dst_labfile, topo, id_by_name)

# -------------------------
# Main
# -------------------------
def main():
    load_dotenv_safely(PROJECT_ROOT / ".env")

    parser = argparse.ArgumentParser(
        description="Despliegue IaC EVE-NG desde JSON (básico/intermedio/avanzado)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--nivel", choices=["basico", "intermedio", "avanzado"], required=True)
    parser.add_argument("--dst", required=True, help="Nombre del laboratorio destino (.unl)")

    parser.add_argument("--base", default=os.getenv("EVE_BASE", DEFAULT_BASE), help="URL base de EVE-NG")
    parser.add_argument("--user", default=os.getenv("EVE_USER", DEFAULT_USER), help="Usuario de EVE-NG")
    parser.add_argument("--pass", dest="password", default=os.getenv("EVE_PASS", DEFAULT_PASS), help="Contraseña de EVE-NG")

    parser.add_argument("--force", action="store_true", help="Eliminar el laboratorio destino si ya existe")
    parser.add_argument(
        "--visibility",
        type=int,
        default=DEFAULT_BRIDGE_VISIBILITY,
        help="Visibilidad inicial del bridge al momento de crearlo (0=oculto, 1=visible)",
    )

    parser.add_argument("--dry-run", action="store_true", help="Solo muestra el plan, sin crear nada")
    parser.add_argument("--validate", action="store_true", help="Valida el JSON antes de desplegar")
    parser.add_argument("--precheck", action="store_true", help="Muestra advertencias antes del despliegue")

    parser.add_argument("--no-log", action="store_true", help="No guardar archivo de log")

    parser.add_argument("--start", action="store_true", help="Iniciar nodos al finalizar el despliegue")
    parser.add_argument("--apply-bootstrap", action="store_true", help="Aplicar configuraciones por consola")

    args = parser.parse_args()

    topo = load_topology(args.nivel)

    if args.validate:
        errs = validate_topology(topo)
        if errs:
            print("❌ Error de validación del JSON:")
            for e in errs:
                print(" -", e)
            sys.exit(2)
        print("✅ Validación completada correctamente.")

    if args.precheck:
        warns = precheck_topology(topo)
        if warns:
            print("⚠️ Advertencias detectadas:")
            for w in warns:
                print(" -", w)
        else:
            print("✅ No se detectaron advertencias relevantes.")

    log, log_path = make_logger(args.dst, args.nivel, enabled=(not args.no_log))

    base = (args.base or "").strip()
    if base and not base.startswith("http"):
        base = "http://" + base

    if not base:
        raise RuntimeError("Debes indicar la URL base de EVE-NG con --base o en la variable EVE_BASE.")

    api = EveAPI(base=base, user=args.user, password=args.password, logger=log)

    try:
        deploy(
            api=api,
            topo=topo,
            dst_labfile=args.dst,
            force=args.force,
            visibility=int(args.visibility),
            dry_run=args.dry_run,
            start_flag=args.start,
            bootstrap_flag=args.apply_bootstrap,
        )
        if log_path:
            print(f"🧾 Log guardado en: {log_path}")
    except FileNotFoundError as e:
        print(f"❌ Error: no se encontró el archivo requerido. Detalle: {e}")
    except requests.exceptions.ConnectTimeout:
        print(f"❌ Error: se agotó el tiempo de conexión con EVE-NG en {base}")
    except requests.exceptions.ConnectionError:
        print(f"❌ Error: no se pudo establecer conexión con EVE-NG en {base}")
    except ValueError as e:
        print(f"❌ Error de validación o de interfaces: {e}")
    except RuntimeError as e:
        print(f"❌ Error en la ejecución: {e}")
    except Exception as e:
        print(f"❌ Error inesperado: {e}")

if __name__ == "__main__":
    main()