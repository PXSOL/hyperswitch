#!/usr/bin/env python3
# =============================================================================
#  Fiserv IPG (First Data gateway/v2) — Harness de Homologación
# =============================================================================
#  Corre TODOS los casos del checklist de homologación de Fiserv contra el
#  gateway CERT y deja la evidencia lista para la planilla (Caso | Fecha | OrderID).
#
#  Los 26 casos corren HEADLESS, incluidos los 3DS con Challenge: el ACS de test
#  (Modirum) se maneja por HTTP desde acá — se postea el cReq, se elige el
#  resultado en el simulador (Yes/Attempt/No/Rejected/Unavailable) y se recupera
#  el cRes del form de vuelta. No hace falta browser.
#
#  También hay modo browser (`serve`) para dejar evidencia del flujo real con
#  redirect al ACS, que es lo que hará Hyperswitch en producción.
#
#  Solo stdlib de Python 3.
#
#  ─────────────────────────────────────────────────────────────────────────
#  USO
#  ─────────────────────────────────────────────────────────────────────────
#    ./fiserv_homologacion.py check          # config + conectividad
#    ./fiserv_homologacion.py ar-basic       # sale/USD/zeroauth/cuotas/DMN/inquiry/void/return
#    ./fiserv_homologacion.py ar-token       # TOKEN GW + TOKEN MTRG
#    ./fiserv_homologacion.py ar-3ds         # los 16 casos 3DS, headless de punta a punta
#    ./fiserv_homologacion.py ar-3ds-alt     # las 3 tarjetas alternativas de la guía
#    ./fiserv_homologacion.py ar-diag        # pruebas de control de los casos que no cierran
#    ./fiserv_homologacion.py uy-basic       # básicos de Uruguay
#    ./fiserv_homologacion.py all            # todo
#    ./fiserv_homologacion.py serve [puerto] # modo browser (3DS real con redirect al ACS)
#    ./fiserv_homologacion.py report         # re-imprime la planilla de la última corrida
#
#  Evidencia por corrida en  ./fiserv_homologacion_logs/<timestamp>/
#      evidencia.jsonl   request + response completos de cada paso
#      planilla.md       tabla lista para pegar en el checklist de Fiserv
#      planilla.csv      lo mismo en CSV
# =============================================================================
import base64, csv, hashlib, hmac, json, os, re, ssl, sys, time, uuid
import html as htmlmod
import http.cookiejar
import urllib.error, urllib.parse, urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ============================== CONFIG =======================================
SELFDIR = os.path.dirname(os.path.abspath(__file__))

# Credenciales locales (carpeta gitignored). Mismo archivo que usa el .sh:
#   AR_KEY=... / AR_SECRET=... / UY_KEY=... / etc.
def _load_creds_env():
    path = os.path.join(SELFDIR, "fiserv_homologacion_secrets", "creds.env")
    if not os.path.exists(path):
        return
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

_load_creds_env()

def env(name, default):
    return os.environ.get(name, default)

URL = env("FISERV_URL", "https://cert.api.firstdata.com/gateway/v2")

# Las credenciales NO viven en este archivo: salen de fiserv_homologacion_secrets/creds.env
# (gitignoreado) o del entorno. Así el harness se puede commitear sin secretos.
REGIONS = {
    "ar": {
        "key":      env("AR_KEY", ""),
        "secret":   env("AR_SECRET", ""),
        "store":    env("AR_STORE", "5926072901"),
        "currency": env("AR_CURRENCY", "ARS"),
        "card":     env("AR_CARD", "5165850000000008"),   # Mastercard AR
    },
    "uy": {
        "key":      env("UY_KEY", ""),
        "secret":   env("UY_SECRET", ""),
        "store":    env("UY_STORE", "7726072903"),
        "currency": env("UY_CURRENCY", "UYU"),
        "card":     env("UY_CARD", "4103770000000006"),   # Visa Uruguay crédito (Apéndice IV)
    },
}

def require_creds(*regions):
    faltan = [r.upper() for r in regions if not (REGIONS[r]["key"] and REGIONS[r]["secret"])]
    if faltan:
        sys.stderr.write(
            "Faltan credenciales de %s.\n"
            "Poné %s_KEY / %s_SECRET en fiserv_homologacion_secrets/creds.env "
            "(o exportalas como variables de entorno).\n"
            % (", ".join(faltan), faltan[0], faltan[0]))
        sys.exit(2)

# Tiendas específicas del checklist: cada tipo de token va a la suya y NO son
# intercambiables (Parte 11 del doc consolidado).
AR_STORE_TOKEN_GW   = env("AR_STORE_TOKEN_GW", "5926072902")
AR_STORE_TOKEN_MTRG = env("AR_STORE_TOKEN_MTRG", "5926072901")

AMOUNT       = env("AMOUNT", "1000.00")          # 1000.00 = aprobada (tabla de simulación por importe)
AMOUNT_HALF  = env("AMOUNT_HALF", "500.00")
INSTALLMENTS = int(env("INSTALLMENTS", "6"))

CVV, EXP_M, EXP_Y = "123", "12", "29"

# La guía pide que el methodNotificationURL sea identificable de forma única; se
# le agrega el orderId como query string. example.com es un dominio reservado por
# IANA que no recibe nada: no corresponde usarlo como termURL en homologación.
BASE_3DS_URL = env("BASE_3DS_URL", "https://www.pxsol.com")

# Tarjetas del checklist de homologación
CARD_TOKEN_GW   = env("CARD_TOKEN_GW", "5165850000000008")     # tienda 5926072902
CARD_TOKEN_MTRG = env("CARD_TOKEN_MTRG", "4622943127032366")   # tienda 5926072901

# Network Token passthrough (§9.2): el criptograma es obligatorio por doc y
# dinámico por transacción. El de acá es el EJEMPLO del doc; en producción sale
# del TSP (MDES / VTS). El gateway valida largo: entre 20 y 256 caracteres.
NETTOKEN_CRYPTOGRAM = env("NETTOKEN_CRYPTOGRAM", "AgAAAAoAPlUosiUEDQNSgElQEAA=")
NETTOKEN_EXP_M = env("NETTOKEN_EXP_M", "12")
NETTOKEN_EXP_Y = env("NETTOKEN_EXP_Y", "29")

# ---- Tarjetas 3DS del checklist (Parte 11) ----
# id -> (numero, descripcion, flujo, resultado_esperado)
#   flujo: fric | method | challenge | challenge_method | dataonly
#   acs_result: para los "configurable", qué botón del simulador apretar
CARDS_3DS = [
    ("fric-y",  "4147463011110083", "Frictionless Authenticated",              "fric",  None, "1"),
    ("fric-n",  "4147463011110091", "Frictionless Not Authenticated",          "fric",  None, "3"),
    ("fric-a",  "4147463011110117", "Frictionless Attempted Authentication",   "fric",  None, "4"),
    ("fric-r",  "4147463011110042", "Frictionless Rejected Authentication",    "fric",  None, "3"),
    ("fric-u",  "4147463011110067", "Frictionless Unable to Authenticate",     "fric",  None, "6"),

    ("mth-y",   "4099000000001978", "3DSMethod Authenticated",                 "method", None, "1"),
    ("mth-n",   "4265880000000015", "3DSMethod Not Authenticated",             "method", None, "3"),
    ("mth-a",   "4149011500000519", "3DSMethod Attempted Authentication",      "method", None, "4"),
    ("mth-r",   "4016360000000085", "3DSMethod Rejected Authentication",       "method", None, "3"),
    ("mth-u",   "4265880000000080", "3DSMethod Unable to Authenticate",        "method", None, "6"),

    ("cha-r",   "4147463011110034", "Challenge - R",                           "challenge", None, "3"),
    ("cha-1",   "4147463011110059", "Challenge - configurable / response 1",   "challenge", "y", "1"),
    ("cha-4",   "4147463011110059", "Challenge - configurable / response 4",   "challenge", "a", "4"),
    ("cha-3",   "4147463011110059", "Challenge - configurable / response 3",   "challenge", "n", "3"),
    ("cha-6",   "4147463011110059", "Challenge - configurable / response 6",   "challenge", "u", "6"),

    ("chm-r",   "4149011500000535", "Challenge+Method - R",                    "challenge", None, "3"),
    ("chm-1",   "4265880000000064", "Challenge+Method - configurable / resp 1", "challenge", "y", "1"),
    ("chm-4",   "4265880000000064", "Challenge+Method - configurable / resp 4", "challenge", "a", "4"),
    ("chm-3",   "4265880000000064", "Challenge+Method - configurable / resp 3", "challenge", "n", "3"),
    ("chm-6",   "4265880000000064", "Challenge+Method - configurable / resp 6", "challenge", "u", "6"),

    ("dataonly", "5239290700000028", "DataOnly (Mastercard, messageCategory 80)", "dataonly", None, "A"),
]

# Alternativas que la guía de integración asigna a esos mismos escenarios, para
# las 3 tarjetas donde el checklist no coincide con ella. Se corren aparte
# (`ar-3ds-alt`) como evidencia para consultarle a Fiserv cuál vale. Verificado
# en vivo: solo "3DSMethod Rejected" difiere de verdad.
CARDS_3DS_ALT = [
    ("alt-mth-n", "4099000000001986", "[guía] 3DSMethod Not Authenticated", "method", None, "3"),
    ("alt-mth-r", "4265880000000031", "[guía] 3DSMethod Rejected Authentication", "method", None, "3"),
    ("alt-chm-r", "4147463011110034", "[guía] Challenge+Method - R", "challenge", None, "3"),
]
CARDS_3DS_BY_ID = {c[0]: c for c in CARDS_3DS + CARDS_3DS_ALT}

# El simulador del ACS de test (Modirum) expone estos botones. Verificado en vivo:
#   y -> responseCode3dSecure 1   |   a -> 4   |   n -> 3   |   r -> 3 (reason 19)   |   u -> 6
ACS_RESULTS = {"y": "Yes", "a": "Attempt", "n": "No", "r": "Rejected", "u": "Unavailable"}

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

RED, GRN, YEL, CYA, BLD, RST = "\033[31m", "\033[32m", "\033[33m", "\033[36m", "\033[1m", "\033[0m"
if not sys.stdout.isatty():
    RED = GRN = YEL = CYA = BLD = RST = ""

# ============================== EVIDENCIA ====================================
class Evidence:
    """Guarda cada paso en JSONL y arma la planilla que pide Fiserv."""

    COLUMNS = ["Caso", "Fecha", "OrderID", "ipgTransactionId", "Estado",
               "responseCode3dSecure", "Esperado", "Veredicto", "Detalle"]

    def __init__(self, runid=None):
        self.runid = runid or datetime.now().strftime("%Y%m%d-%H%M%S")
        self.dir = os.path.join(SELFDIR, "fiserv_homologacion_logs", self.runid)
        os.makedirs(self.dir, exist_ok=True)
        gi = os.path.join(SELFDIR, "fiserv_homologacion_logs", ".gitignore")
        if not os.path.exists(gi):
            with open(gi, "w") as fh:
                fh.write("*\n")
        self.jsonl = os.path.join(self.dir, "evidencia.jsonl")
        self.rows = []

    def step(self, case, method, path, payload, status, response):
        with open(self.jsonl, "a") as fh:
            fh.write(json.dumps({
                "ts": datetime.now().isoformat(timespec="seconds"),
                "case": case, "method": method, "path": path,
                "request": payload, "http": status, "response": response,
            }, ensure_ascii=False) + "\n")

    def record(self, case, resp, order_id=None, expected=None, detail="", blocker=False):
        """resp = dict de la última respuesta del caso.
        blocker=True marca los casos que sabemos que el gateway CERT no permite
        cerrar (config de Fiserv), para que no se confundan con una regresión."""
        st = resp.get("transactionStatus") or resp.get("transactionResult") or resp.get("requestStatus")
        err = resp.get("error") or {}
        s3 = (resp.get("secure3dResponse") or {}).get("responseCode3dSecure")
        if not st and err:
            st = "ERROR %s" % (err.get("code") or "?")
            detail = detail or (err.get("message") or "")
            details = err.get("details")
            if details:
                detail = "%s %s" % (detail, json.dumps(details, ensure_ascii=False))
        if not st and resp.get("paymentToken", {}).get("value"):
            st = "TOKEN_CREADO"

        veredicto = self._verdict(st, s3, expected)
        if blocker and veredicto != "OK":
            veredicto = "BLOQUEADO"
        row = {
            "Caso": case,
            "Fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "OrderID": order_id or resp.get("orderId") or "",
            "ipgTransactionId": resp.get("ipgTransactionId") or "",
            "Estado": st or "?",
            "responseCode3dSecure": s3 or "",
            "Esperado": expected or "",
            "Veredicto": veredicto,
            "Detalle": (detail or "")[:200],
        }
        self.rows.append(row)
        self._print(row)
        return row

    @staticmethod
    def _verdict(st, s3, expected):
        if expected is None:
            # Casos sin 3DS: aprobado, capturado o token creado = OK
            return "OK" if st in ("APPROVED", "TOKEN_CREADO", "CAPTURED", "SUCCESS") else "REVISAR"
        if s3 is None:
            return "FALLA"
        return "OK" if s3 == expected else "FALLA"

    @staticmethod
    def _print(row):
        mark = {"OK": GRN + "OK " + RST, "FALLA": RED + "FALLA" + RST,
                "BLOQUEADO": YEL + "BLOQ " + RST}.get(row["Veredicto"], YEL + "?  " + RST)
        extra = ""
        if row["responseCode3dSecure"]:
            extra = " 3ds=%s" % row["responseCode3dSecure"]
            if row["Esperado"]:
                extra += "(esp %s)" % row["Esperado"]
        print("  %s %-46s %-17s%s %s" % (mark, row["Caso"][:46], row["Estado"], extra,
                                         (RED + row["Detalle"][:60] + RST) if row["Veredicto"] == "FALLA" and row["Detalle"] else ""))

    def flush(self):
        if not self.rows:
            return
        csv_path = os.path.join(self.dir, "planilla.csv")
        with open(csv_path, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=self.COLUMNS)
            w.writeheader()
            w.writerows(self.rows)
        md_path = os.path.join(self.dir, "planilla.md")
        with open(md_path, "w") as fh:
            fh.write("# Homologación Fiserv IPG — corrida %s\n\n" % self.runid)
            fh.write("| " + " | ".join(self.COLUMNS) + " |\n")
            fh.write("|" + "|".join(["---"] * len(self.COLUMNS)) + "|\n")
            for r in self.rows:
                fh.write("| " + " | ".join(str(r[c]).replace("|", "\\|") for c in self.COLUMNS) + " |\n")
        return md_path

    def summary(self):
        ok = sum(1 for r in self.rows if r["Veredicto"] == "OK")
        bad = sum(1 for r in self.rows if r["Veredicto"] == "FALLA")
        blocked = sum(1 for r in self.rows if r["Veredicto"] == "BLOQUEADO")
        other = len(self.rows) - ok - bad - blocked
        md = self.flush()
        print()
        print(BLD + "=" * 78 + RST)
        print("  %sOK: %d%s   %sFALLA: %d%s   %sbloqueados por Fiserv: %d%s   %sa revisar: %d%s   (total %d)"
              % (GRN, ok, RST, RED, bad, RST, YEL, blocked, RST, YEL, other, RST, len(self.rows)))
        print("  Evidencia: %s%s%s" % (CYA, self.dir, RST))
        if md:
            print("  Planilla:  %s%s%s" % (CYA, md, RST))
        return bad

EV = None  # Evidence activa

# ============================== API ==========================================
def sign(key, secret, crid, ts, payload):
    raw = (key + crid + ts + payload).encode()
    return base64.b64encode(hmac.new(secret.encode(), raw, hashlib.sha256).digest()).decode()

def api(region, method, path, payload=None, case=None):
    """Devuelve (http_status, dict). GET firma con payload vacío."""
    c = REGIONS[region]
    crid, ts = str(uuid.uuid4()), str(int(time.time() * 1000))
    body = "" if payload is None else json.dumps(payload, separators=(",", ":"))
    req = urllib.request.Request(URL + path, data=(body.encode() if payload is not None else None), method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Api-Key", c["key"])
    req.add_header("Client-Request-Id", crid)
    req.add_header("Timestamp", ts)
    req.add_header("Message-Signature", sign(c["key"], c["secret"], crid, ts, body))
    try:
        with urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=60) as r:
            status, text = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode()
    except Exception as e:                                    # timeout / DNS / TLS
        status, text = 0, json.dumps({"error": {"code": "TRANSPORT", "message": str(e)}})
    try:
        data = json.loads(text)
    except ValueError:
        data = {"error": {"code": "NON_JSON", "message": text[:500]}}
    if EV and case:
        EV.step(case, method, path, payload, status, data)
    return status, data

_ORDER_SEQ = [0]
def new_order_id(tag):
    # IPG limita merchantTransactionId a 40 caracteres; el orderId se mantiene
    # igual para que la planilla y los logs de Fiserv coincidan.
    _ORDER_SEQ[0] += 1
    return ("PX-%d-%02d-%s" % (int(time.time()), _ORDER_SEQ[0], tag))[:40]

def payment_card(number, cvv=CVV, m=EXP_M, y=EXP_Y):
    pc = {"number": number, "expiryDate": {"month": m, "year": y}}
    if cvv:
        pc["securityCode"] = cvv
    return pc

# ============================== BÁSICOS ======================================
def sale_payload(region, store, card, order_id, amount=None, currency=None,
                 order_extra=None, extra=None, auth_request=None, cvv=CVV):
    c = REGIONS[region]
    order = {"orderId": order_id}
    if order_extra:
        order.update(order_extra)
    p = {
        "requestType": "PaymentCardSaleTransaction",
        "merchantTransactionId": order_id[:40],
        "storeId": store,
        "transactionAmount": {"total": amount or AMOUNT, "currency": currency or c["currency"]},
        "order": order,
        "paymentMethod": {"paymentCard": payment_card(card, cvv=cvv)},
    }
    if auth_request:
        p["authenticationRequest"] = auth_request
    if extra:
        p.update(extra)
    return p

def run_basic(region):
    c = REGIONS[region]
    store, card, R = c["store"], c["card"], region.upper()
    print("%s%s== %s — Transacciones básicas (tienda %s) ==%s" % (BLD, CYA, R, store, RST))

    def sale(case, tag, **kw):
        oid = new_order_id(tag)
        p = sale_payload(region, store, card, oid, **kw)
        _, r = api(region, "POST", "/payments", p, case=case)
        return r, oid

    # 1) sale en 1 pago
    r, oid = sale("%s SALE 1 pago" % R, "sale")
    EV.record("%s SALE 1 pago" % R, r, oid)

    # 2) sale en 1 pago con DÓLAR
    r, oid = sale("%s SALE 1 pago USD" % R, "saleusd", currency="USD")
    EV.record("%s SALE 1 pago USD" % R, r, oid)

    # 3) ZEROAUTH (monto 0)
    r, oid = sale("%s SALE ZEROAUTH" % R, "zeroauth", amount="0")
    EV.record("%s SALE ZEROAUTH" % R, r, oid)

    # 4) sale en cuotas
    r, oid = sale("%s SALE cuotas (%d)" % (R, INSTALLMENTS), "cuotas",
                  order_extra={"installmentOptions": {"numberOfInstallments": INSTALLMENTS}})
    EV.record("%s SALE cuotas (%d)" % (R, INSTALLMENTS), r, oid)

    # 5) DYNAMIC MERCHANT NAME — softDescriptor va DENTRO de order; a nivel raíz
    #    el gateway responde "No field named 'softDescriptor' exists for class
    #    PaymentCardSaleTransaction".
    r, oid = sale("%s DYNAMIC MERCHANT NAME" % R, "dmn",
                  order_extra={"softDescriptor": {"dynamicMerchantName": "PXSOL*Reservas"}})
    EV.record("%s DYNAMIC MERCHANT NAME" % R, r, oid)

    # 6) INQUIRY — por ipgTransactionId y por orderId (el checklist pide INQUIRY ORDER)
    r, oid = sale("%s (venta para inquiry)" % R, "inq")
    ipg = r.get("ipgTransactionId")
    if ipg:
        _, q = api(region, "GET", "/payments/%s?storeId=%s" % (ipg, store),
                   case="%s INQUIRY by transactionId" % R)
        EV.record("%s INQUIRY by transactionId" % R, q, oid)
    _, q = api(region, "GET", "/orders/%s?storeId=%s" % (urllib.parse.quote(oid), store),
               case="%s INQUIRY ORDER" % R)
    # /orders devuelve {"transactions":[...]}: el estado real está adentro
    inner = (q.get("transactions") or [{}])[0] if q.get("transactions") else q
    inner = dict(inner)
    inner.setdefault("orderId", q.get("orderId"))
    if q.get("error"):
        inner["error"] = q["error"]
    EV.record("%s INQUIRY ORDER" % R, inner, oid)

    # 7) VOID (anulación) — sobre una venta nueva
    r, oid = sale("%s (venta para void)" % R, "void")
    ipg = r.get("ipgTransactionId")
    if ipg:
        _, v = api(region, "POST", "/payments/%s" % ipg,
                   {"requestType": "VoidTransaction", "storeId": store},
                   case="%s VOID (anulación)" % R)
        EV.record("%s VOID (anulación)" % R, v, oid)
    else:
        EV.record("%s VOID (anulación)" % R, r, oid, detail="no hubo venta previa que anular")

    # 8) RETURN total
    r, oid = sale("%s (venta para return total)" % R, "rettot")
    ipg = r.get("ipgTransactionId")
    if ipg:
        _, v = api(region, "POST", "/payments/%s" % ipg,
                   {"requestType": "ReturnTransaction", "storeId": store,
                    "transactionAmount": {"total": AMOUNT, "currency": c["currency"]}},
                   case="%s RETURN total" % R)
        EV.record("%s RETURN total" % R, v, oid)
    else:
        EV.record("%s RETURN total" % R, r, oid, detail="no hubo venta previa")

    # 9) RETURN parcial
    r, oid = sale("%s (venta para return parcial)" % R, "retpar")
    ipg = r.get("ipgTransactionId")
    if ipg:
        _, v = api(region, "POST", "/payments/%s" % ipg,
                   {"requestType": "ReturnTransaction", "storeId": store,
                    "transactionAmount": {"total": AMOUNT_HALF, "currency": c["currency"]}},
                   case="%s RETURN parcial" % R)
        EV.record("%s RETURN parcial" % R, v, oid)
    else:
        EV.record("%s RETURN parcial" % R, r, oid, detail="no hubo venta previa")

# ============================== TOKENIZACIÓN =================================
def run_token():
    region = "ar"
    print("%s%s== AR — Tokenización ==%s" % (BLD, CYA, RST))

    # --- TOKEN GW: tokenización IPG (§9.1), tienda 5926072902 ---
    store = AR_STORE_TOKEN_GW
    p = {"requestType": "PaymentCardPaymentTokenizationRequest", "storeId": store,
         "paymentCard": payment_card(CARD_TOKEN_GW),
         "createToken": {"reusable": True, "declineDuplicates": False}}
    _, r = api(region, "POST", "/payment-tokens", p, case="AR CREATE TOKEN GW")
    EV.record("AR CREATE TOKEN GW (IPG, tienda %s)" % store, r)
    token = (r.get("paymentToken") or {}).get("value")

    if token:
        oid = new_order_id("tokgw")
        p = {"requestType": "PaymentTokenSaleTransaction", "merchantTransactionId": oid[:40],
             "storeId": store,
             "transactionAmount": {"total": AMOUNT, "currency": REGIONS[region]["currency"]},
             "order": {"orderId": oid, "installmentOptions": {"numberOfInstallments": INSTALLMENTS}},
             "paymentMethod": {"paymentToken": {"value": token, "tokenOriginStoreId": store}}}
        _, s = api(region, "POST", "/payments", p, case="AR SALE cuotas TOKEN GW")
        EV.record("AR SALE en cuotas (%d) con TOKEN GW" % INSTALLMENTS, s, oid)
    else:
        EV.record("AR SALE en cuotas con TOKEN GW", {}, detail="no se obtuvo el token GW")

    # --- TOKEN MTRG: Network Token, tienda 5926072901 ---
    # El checklist da la tarjeta CON CVV, así que el caso es el flujo "OnTheGo"
    # del manual MTRG: se manda el PAN real (con CVV) en una venta normal y
    # Fiserv le pide el Network Token a la marca. NO lleva tokenCryptogram: eso
    # es del flujo passthrough, donde el comercio ya tiene su propio TSP.
    # Se verifica en la respuesta que la sustitución ocurrió comparando
    # fundingCardNumber.bin (PAN) contra paymentCard.bin (Network Token).
    store = AR_STORE_TOKEN_MTRG

    def mtrg_onthego(case, cuotas=None):
        oid = new_order_id("mtrg")
        order = {"orderId": oid}
        if cuotas:
            order["installmentOptions"] = {"numberOfInstallments": cuotas}
        p = {"requestType": "PaymentCardSaleTransaction", "merchantTransactionId": oid[:40],
             "storeId": store,
             "transactionAmount": {"total": AMOUNT, "currency": REGIONS[region]["currency"]},
             "order": order,
             "paymentMethod": {"paymentCard": payment_card(CARD_TOKEN_MTRG)}}
        _, r = api(region, "POST", "/payments", p, case=case)
        return r, oid

    def token_substituted(r):
        pc = ((r.get("paymentMethodDetails") or {}).get("paymentCard") or {})
        pan_bin = (pc.get("fundingCardNumber") or {}).get("bin")
        tok_bin = pc.get("bin")
        if not (pan_bin and tok_bin):
            return None
        return pan_bin != tok_bin

    # El checklist pide "en cuotas". El gateway CERT lo rechaza con 11101
    # "installment only supported for local cards"; se corren las dos variantes
    # y quedan las dos como evidencia.
    r, oid = mtrg_onthego("AR SALE cuotas TOKEN MTRG", INSTALLMENTS)
    EV.record("AR SALE en cuotas (%d) con TOKEN MTRG" % INSTALLMENTS, r, oid, blocker=True,
              detail="11101 'installment only supported for local cards'. Consultar a Fiserv.")

    r, oid = mtrg_onthego("AR SALE TOKEN MTRG 1 pago")
    sub = token_substituted(r)
    pc = ((r.get("paymentMethodDetails") or {}).get("paymentCard") or {})
    det = ("Network Token provisionado: PAN %s/%s -> token %s/%s" % (
              (pc.get("fundingCardNumber") or {}).get("bin"), (pc.get("fundingCardNumber") or {}).get("last4"),
              pc.get("bin"), pc.get("last4"))) if sub else \
          ("ATENCIÓN: no hubo sustitución por Network Token (bin del PAN y del token son iguales)"
           if sub is False else "")
    EV.record("AR SALE 1 pago con TOKEN MTRG (sin cuotas)", r, oid, detail=det)
    if sub is False:
        print("      %s⚠ el gateway no sustituyó por Network Token%s" % (YEL, RST))

# ============================== 3DS ==========================================
def auth_request(flow, term_url, method_url):
    """authenticationRequest según el flujo. Data Only usa la clase base."""
    if flow == "dataonly":
        # §10.1.6 — solo Mastercard. La subclase Secure3D21AuthenticationRequest
        # NO acepta messageCategory (el gateway responde INVALID_INPUT).
        return {"authenticationType": "Secure3DAuthenticationRequest",
                "termURL": term_url, "methodNotificationURL": method_url,
                "messageCategory": "80"}
    return {"authenticationType": "Secure3D21AuthenticationRequest",
            "termURL": term_url, "methodNotificationURL": method_url,
            "challengeIndicator": "01", "challengeWindowSize": "05"}

def patch_3ds(region, store, ipg, body, case):
    """Los updates de 3DS son PATCH /payments/{id}.
    Con POST el gateway responde INVALID_INPUT 'Request type missing'."""
    body = dict(body)
    body["authenticationType"] = "Secure3D21AuthenticationUpdateRequest"
    body["storeId"] = store
    return api(region, "PATCH", "/payments/%s" % ipg, body, case=case)

# ---- driver headless del ACS de test (Modirum) ----
def _acs_post(opener, url, fields):
    req = urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode(), method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", UA)
    try:
        with opener.open(req, timeout=60) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return 0, "<!-- transport error: %s -->" % e

def _find_input(html, name):
    pat = r'<input\b[^>]*\bname\s*=\s*["\']%s["\'][^>]*>' % re.escape(name)
    m = re.search(pat, html, re.I)
    if not m:
        pat2 = r'<input\b(?=[^>]*\bvalue\s*=)[^>]*\bname\s*=\s*["\']%s["\'][^>]*>' % re.escape(name)
        m = re.search(pat2, html, re.I)
    if not m:
        return None
    v = re.search(r'\bvalue\s*=\s*["\']([^"\']*)["\']', m.group(0), re.I)
    return v.group(1) if v else None

def _find_cres(html):
    for name in ("cres", "cRes", "CRes", "PaRes"):
        v = _find_input(html, name)
        if v:
            return v
    return None

def _form_action(html):
    m = re.search(r'<form\b[^>]*\baction\s*=\s*["\']([^"\']+)["\']', html, re.I)
    return htmlmod.unescape(m.group(1)) if m else None

def _parse_form(html):
    """(action, {name: value}) del primer <form> del HTML, con entidades resueltas."""
    fm = re.search(r'<form\b[^>]*>(.*?)</form>', html, re.S | re.I)
    if not fm:
        return None, {}
    action = _form_action(fm.group(0))
    fields = {}
    for tag in re.finditer(r'<input\b[^>]*>', fm.group(1), re.I):
        n = re.search(r'\bname\s*=\s*["\']([^"\']+)["\']', tag.group(0), re.I)
        v = re.search(r'\bvalue\s*=\s*["\']([^"\']*)["\']', tag.group(0), re.I)
        if n:
            fields[htmlmod.unescape(n.group(1))] = htmlmod.unescape(v.group(1)) if v else ""
    return action, fields

def drive_method(method_form, log=print):
    """Ejecuta el methodForm contra el ACS igual que lo haría el iframe oculto del
    browser. El ACS responde con el form que postea threeDSMethodData al
    methodNotificationURL: si ese form aparece, la notificación se emitió de
    verdad y recién ahí corresponde declarar RECEIVED."""
    action, fields = _parse_form(method_form or "")
    if not action or not fields:
        log("      %sno se pudo parsear el methodForm%s" % (YEL, RST))
        return False
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    status, html = _acs_post(opener, action, fields)
    _, notif = _parse_form(html)
    received = bool(notif.get("threeDSMethodData") or notif.get("3DSMethodData"))
    log("      3DSMethod ejecutado contra el ACS -> notificación %s"
        % ("recibida" if received else "NO recibida (http=%s)" % status))
    return received

def session_data(params):
    """threeDSSessionData / sessiondata, sin distinguir mayúsculas. Vacío si no viene."""
    for k, v in (params or {}).items():
        if k.lower() in ("threedssessiondata", "sessiondata") and v:
            return v
    return ""

def drive_acs(params, acs_result, log=print):
    """POST cReq al ACS. Si aparece el simulador interactivo, aprieta el botón
    pedido. Devuelve el cRes o None."""
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    fields = {"creq": params["cReq"]}
    sess = session_data(params)
    if sess:
        fields["threeDSSessionData"] = sess
    status, html = _acs_post(opener, params["acsURL"], fields)
    cres = _find_cres(html)
    hops = 0
    while not cres and hops < 3:
        action = _form_action(html)
        if not action:
            break
        action = urllib.parse.urljoin(params["acsURL"], action)
        result = acs_result or "y"
        log("      ACS simulador -> result=%s (%s)" % (result, ACS_RESULTS.get(result, "?")))
        status, html = _acs_post(opener, action, {"result": result, "slowdownMs": "0"})
        cres = _find_cres(html)
        hops += 1
    if not cres:
        log("      %sel ACS no devolvió cRes (http=%s, %d bytes)%s" % (YEL, status, len(html), RST))
    return cres

def run_3ds_case(region, card_id, term_url=None, method_url=None):
    """Corre un caso 3DS de punta a punta, headless. Devuelve (resp, order_id)."""
    cid, number, label, flow, acs_result, expected = CARDS_3DS_BY_ID[card_id]
    store = REGIONS[region]["store"]
    case = "3DS %s" % label

    oid = new_order_id("3ds-" + cid)
    ref = urllib.parse.quote(oid)
    term_url = term_url or "%s/3ds/return?ref=%s" % (BASE_3DS_URL, ref)
    method_url = method_url or "%s/3ds/method?ref=%s" % (BASE_3DS_URL, ref)
    p = sale_payload(region, store, number, oid,
                     auth_request=auth_request(flow, term_url, method_url))
    _, r = api(region, "POST", "/payments", p, case=case + " [init]")
    ipg = r.get("ipgTransactionId")

    # Paso 3DSMethod: se ejecuta el methodForm contra el ACS (lo mismo que hace el
    # iframe oculto del browser) y el status se declara según lo que pasó de
    # verdad, no por defecto.
    ar = r.get("authenticationResponse") or {}
    if ar.get("secure3dMethod") and ipg:
        received = drive_method((ar.get("secure3dMethod") or {}).get("methodForm"))
        _, r = patch_3ds(region, store, ipg,
                         {"methodNotificationStatus": "RECEIVED" if received
                          else "EXPECTED_BUT_NOT_RECEIVED"},
                         case + " [methodNotificationStatus]")
        ar = r.get("authenticationResponse") or {}

    # Paso Challenge: redirect al ACS y vuelta con el cRes
    params = ar.get("params")
    if params and params.get("acsURL") and ipg:
        cres = drive_acs(params, acs_result)
        if cres:
            _, r = patch_3ds(region, store, ipg, {"acsResponse": {"cRes": cres}}, case + " [cRes]")
        else:
            r = dict(r)
            r.setdefault("error", {})["message"] = "no se pudo obtener el cRes del ACS"

    return r, oid, label, expected

def run_3ds(region="ar", cards=None, title="3D Secure (casos del checklist, headless)"):
    print("%s%s== %s — %s ==%s" % (BLD, CYA, region.upper(), title, RST))
    print("  El challenge se resuelve contra el simulador del ACS de test; no hace falta browser.")
    for cid, number, label, flow, acs_result, expected in (cards or CARDS_3DS):
        r, oid, label, expected = run_3ds_case(region, cid)
        detail, blocker = "", False
        if flow == "dataonly":
            detail = ("Data Only exige que Fiserv habilite Mastercard Insights en la tienda. "
                      "El 50655 / código 8 se reproduce con cualquier MC y en las dos tiendas.")
            blocker = True
        EV.record("3DS %s" % label, r, oid, expected=expected, detail=detail, blocker=blocker)

# ============================== DIAGNÓSTICO ==================================
# Pruebas de control para los tres casos que no cierran. Corren dentro de la
# misma corrida que el checklist para que cada afirmación que le mandemos a
# Fiserv tenga su apiTraceId en la evidencia adjunta.
def run_diag(region="ar"):
    print("%s%s== Diagnóstico de los casos que no cierran ==%s" % (BLD, CYA, RST))
    cur = REGIONS[region]["currency"]

    def sale_3ds(case, card, store, ar_block, detail=""):
        oid = new_order_id("diag")
        p = sale_payload(region, store, card, oid, auth_request=ar_block)
        _, r = api(region, "POST", "/payments", p, case=case)
        EV.record(case, r, oid, detail=detail)
        return r

    print("  -- Data Only: la modalidad no responde en ninguna variante --")
    base = lambda **kw: dict({"authenticationType": "Secure3DAuthenticationRequest",
                              "termURL": BASE_3DS_URL + "/3ds/return",
                              "methodNotificationURL": BASE_3DS_URL + "/3ds/method"}, **kw)
    st901, st902 = REGIONS[region]["store"], AR_STORE_TOKEN_GW
    sale_3ds("DIAG DataOnly MC 5239290700000028 tienda %s" % st901, "5239290700000028", st901,
             base(messageCategory="80"), "el caso del checklist")
    sale_3ds("DIAG DataOnly MC 5239290700000028 tienda %s" % st902, "5239290700000028", st902,
             base(messageCategory="80"), "misma prueba en la otra tienda")
    sale_3ds("DIAG DataOnly MC 5165850000000008 tienda %s" % st901, "5165850000000008", st901,
             base(messageCategory="80"), "la Mastercard que usa el ejemplo de Data Only de la guia")
    sale_3ds("DIAG control: misma MC SIN messageCategory", "5239290700000028", st901,
             base(), "control: el servicio 3DS de la tienda funciona (WAITING + 3DS 2.2)")
    sale_3ds("DIAG control: misma MC con messageCategory 01", "5239290700000028", st901,
             base(messageCategory="01"), "control: el campo messageCategory se procesa")
    sale_3ds("DIAG control: VISA con messageCategory 80", "4147463011110083", st901,
             base(messageCategory="80"), "control: el gateway valida la marca (50738)")

    print("  -- Escenario 'Rejected Authentication': las 5 tarjetas de la documentacion --")
    for card, donde in [("4147463011110042", "Frictionless Flow"),
                        ("4016360000000085", "Frictionless Flow / la del checklist"),
                        ("5188340000000052", "Frictionless Flow"),
                        ("4265880000000031", "Frictionless Flow + 3DSMethod"),
                        ("5204740000002778", "Frictionless Flow + 3DSMethod")]:
        oid = new_order_id("diag")
        case = "DIAG Rejected %s (%s)" % (card, donde)
        p = sale_payload(region, st901, card, oid,
                         auth_request=auth_request("method", BASE_3DS_URL + "/3ds/return",
                                                   BASE_3DS_URL + "/3ds/method"))
        _, r = api(region, "POST", "/payments", p, case=case + " [init]")
        ar = r.get("authenticationResponse") or {}
        paso = "sin 3DSMethod"
        if ar.get("secure3dMethod"):
            paso = "con 3DSMethod"
            drive_method((ar.get("secure3dMethod") or {}).get("methodForm"))
            _, r = patch_3ds(region, st901, r.get("ipgTransactionId"),
                             {"methodNotificationStatus": "RECEIVED"}, case + " [method]")
        EV.record(case, r, oid, expected="3", detail="documentada como codigo 3 / status R; %s" % paso)

    print("  -- Data Only por passthrough (10.2.2): la tienda SI procesa Data Only --")
    oid = new_order_id("diag")
    p = sale_payload(region, st901, "5239290700000028", oid)
    p["authenticationResult"] = {"authenticationType": "Secure3DAuthenticationResult",
                                 "authenticationResponse": "U",
                                 "cavv": "AAABCZIhcQAAAABZlyFxAAAAAAA=",
                                 "dsTransactionId": "c3b8b3c5-b8b8-4b8b-8b8b-8b8b8b8b8b8b",
                                 "transactionStatus": "Y", "messageCategory": "80"}
    case = "DIAG Data Only por passthrough (authenticationResult)"
    _, r = api(region, "POST", "/payments", p, case=case)
    EV.record(case, r, oid, expected="A",
              detail="cavv de EJEMPLO de la guia: sirve como control de que la tienda procesa Data Only, "
                     "NO para cerrar el caso del checklist")
    for mc in ("02", "01"):
        oid = new_order_id("diag")
        case = "DIAG control: messageCategory %s" % mc
        p = sale_payload(region, st901, "5239290700000028", oid,
                         auth_request=base(messageCategory=mc))
        _, r = api(region, "POST", "/payments", p, case=case)
        EV.record(case, r, oid, detail="control de que el gateway valida el valor de messageCategory")

    print("  -- Cuotas: el 11101 es por tarjeta no local, no por Network Token --")
    for card, etiqueta in [("4704550000000005", "VISA AR estandar"),
                           ("4016360000000085", "VISA que tambien se sustituye por Network Token")]:
        for cuotas in (INSTALLMENTS, None):
            oid = new_order_id("diag")
            order = {"orderId": oid}
            if cuotas:
                order["installmentOptions"] = {"numberOfInstallments": cuotas}
            case = "DIAG cuotas %s %s (%s)" % (card, "%d cuotas" % cuotas if cuotas else "1 pago", etiqueta)
            p = {"requestType": "PaymentCardSaleTransaction", "merchantTransactionId": oid[:40],
                 "storeId": st901, "transactionAmount": {"total": AMOUNT, "currency": cur},
                 "order": order, "paymentMethod": {"paymentCard": payment_card(card)}}
            _, r = api(region, "POST", "/payments", p, case=case)
            pc = ((r.get("paymentMethodDetails") or {}).get("paymentCard") or {})
            f = pc.get("fundingCardNumber") or {}
            EV.record(case, r, oid,
                      detail="PAN %s -> procesado %s (%s)" % (
                          f.get("bin"), pc.get("bin"),
                          "sustituido por Network Token" if f.get("bin") and f.get("bin") != pc.get("bin")
                          else "sin sustitucion"))

    print("  -- TOKEN MTRG flujo Asincrono (HostedDataID): mismo rechazo --")
    _, t = api(region, "POST", "/payment-tokens",
               {"requestType": "PaymentCardPaymentTokenizationRequest", "storeId": AR_STORE_TOKEN_MTRG,
                "paymentCard": {"number": CARD_TOKEN_MTRG,
                                "expiryDate": {"month": EXP_M, "year": EXP_Y}},
                "createToken": {"reusable": True, "declineDuplicates": False}},
               case="DIAG MTRG Asincrono crear HostedDataID")
    pt = t.get("paymentToken") or {}
    EV.record("DIAG MTRG Asincrono crear HostedDataID", t,
              detail="type=%s networkTokenProvisionStatus=%s" % (pt.get("type"), pt.get("networkTokenProvisionStatus")))
    ntok = pt.get("value")
    if ntok:
        for cuotas in (INSTALLMENTS, None):
            oid = new_order_id("diag")
            order = {"orderId": oid}
            if cuotas:
                order["installmentOptions"] = {"numberOfInstallments": cuotas}
            case = "DIAG MTRG Asincrono %s" % ("%d cuotas" % cuotas if cuotas else "1 pago")
            p = {"requestType": "PaymentTokenSaleTransaction", "merchantTransactionId": oid[:40],
                 "storeId": AR_STORE_TOKEN_MTRG,
                 "transactionAmount": {"total": AMOUNT, "currency": cur}, "order": order,
                 "paymentMethod": {"paymentToken": {"value": ntok,
                                                    "tokenOriginStoreId": AR_STORE_TOKEN_MTRG}}}
            _, r = api(region, "POST", "/payments", p, case=case)
            pc = ((r.get("paymentMethodDetails") or {}).get("paymentCard") or {})
            f = pc.get("fundingCardNumber") or {}
            det = ("PAN %s/%s -> Network Token %s/%s" % (f.get("bin"), f.get("last4"), pc.get("bin"), pc.get("last4"))
                   if f.get("bin") and pc.get("bin") and f["bin"] != pc["bin"] else "")
            EV.record(case, r, oid, detail=det)

    print("  -- TOKEN MTRG flujo OnTheGo --")
    for cuotas in (INSTALLMENTS, 3, 1, None):
        oid = new_order_id("diag")
        order = {"orderId": oid}
        if cuotas:
            order["installmentOptions"] = {"numberOfInstallments": cuotas}
        case = "DIAG MTRG OnTheGo %s" % ("%d cuotas" % cuotas if cuotas else "1 pago")
        p = {"requestType": "PaymentCardSaleTransaction", "merchantTransactionId": oid[:40],
             "storeId": AR_STORE_TOKEN_MTRG,
             "transactionAmount": {"total": AMOUNT, "currency": cur},
             "order": order, "paymentMethod": {"paymentCard": payment_card(CARD_TOKEN_MTRG)}}
        _, r = api(region, "POST", "/payments", p, case=case)
        pc = ((r.get("paymentMethodDetails") or {}).get("paymentCard") or {})
        f = pc.get("fundingCardNumber") or {}
        det = ""
        if f.get("bin") and pc.get("bin"):
            det = ("PAN %s/%s -> Network Token %s/%s" % (f.get("bin"), f.get("last4"), pc.get("bin"), pc.get("last4"))
                   if f["bin"] != pc["bin"] else "sin sustitucion por Network Token")
        EV.record(case, r, oid, detail=det)

# ============================== MODO BROWSER =================================
# El ACS le devuelve el form al BROWSER (no al server), y como termURL apunta a
# http://localhost:<puerto>, el POST llega acá. Sirve para dejar evidencia del
# flujo real con redirect, que es lo que hará Hyperswitch.
BROWSER_STATE = {}

def _page(body):
    return ("<!doctype html><meta charset=utf-8><title>Fiserv homologación</title>"
            "<style>body{font-family:system-ui,sans-serif;max-width:860px;margin:24px auto;padding:0 12px}"
            "code{background:#f0f0f0;padding:1px 4px;border-radius:3px}"
            "pre{background:#f7f7f7;padding:10px;overflow:auto;font-size:12px;border-radius:4px}"
            "li{margin:4px 0}.ok{color:#0a0}.bad{color:#c00}</style>" + body)

class BrowserHandler(BaseHTTPRequestHandler):
    region = "ar"
    port = 8099

    def _send(self, html, code=200):
        b = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass

    @property
    def base(self):
        return "http://localhost:%d" % self.port

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path == "/":
            rows = "".join(
                "<li><a href='/start?card=%s'>%s</a> — <code>%s</code>%s</li>"
                % (cid, label, number, (" · ACS result=<code>%s</code>" % acs) if acs else "")
                for cid, number, label, flow, acs, exp in CARDS_3DS)
            self._send(_page("<h2>Fiserv 3DS — modo browser (%s, tienda %s)</h2>"
                             "<p>Elegí un caso. El flujo se completa en este navegador.</p><ul>%s</ul>"
                             % (self.region.upper(), REGIONS[self.region]["store"], rows)))
        elif u.path == "/start":
            cid = q.get("card", ["fric-y"])[0]
            if cid not in CARDS_3DS_BY_ID:
                self._send(_page("<p>Caso desconocido</p><a href='/'>volver</a>"), 404)
                return
            BROWSER_STATE.clear()
            BROWSER_STATE["card"] = cid
            _, number, label, flow, acs_result, expected = CARDS_3DS_BY_ID[cid]
            store = REGIONS[self.region]["store"]
            oid = new_order_id("3ds-" + cid)
            BROWSER_STATE["oid"] = oid
            BROWSER_STATE["expected"] = expected
            BROWSER_STATE["label"] = label
            # §10.1.1 pide que el methodNotificationURL sea identificable de forma
            # única, para poder mapear la notificación del ACS a su transacción
            # sin depender de estado global.
            ref = urllib.parse.quote(oid)
            p = sale_payload(self.region, store, number, oid,
                             auth_request=auth_request(flow,
                                                       "%s/term?ref=%s" % (self.base, ref),
                                                       "%s/method?ref=%s" % (self.base, ref)))
            _, r = api(self.region, "POST", "/payments", p, case="3DS %s [init browser]" % label)
            self._send(self._advance(r))
        elif u.path == "/after-method":
            ipg = BROWSER_STATE.get("ipg")
            got = BROWSER_STATE.get("method_received")
            _, r = patch_3ds(self.region, REGIONS[self.region]["store"], ipg,
                             {"methodNotificationStatus": "RECEIVED" if got else "EXPECTED_BUT_NOT_RECEIVED"},
                             "3DS %s [methodNotificationStatus browser]" % BROWSER_STATE.get("label"))
            self._send(self._advance(r))
        elif u.path == "/method-status":
            body = json.dumps({"received": bool(BROWSER_STATE.get("method_received"))}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif u.path == "/result":
            self._send(self._result(BROWSER_STATE.get("last") or {}))
        else:
            self._send(_page("<p>404</p><a href='/'>menú</a>"), 404)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode(errors="replace")
        # Se guarda el body crudo antes de parsear: si el ACS postea con otro
        # nombre de campo o con otro content-type, queda la evidencia.
        EV.step("ACS -> %s" % u.path, "POST", self.path,
                {"content_type": self.headers.get("Content-Type"), "raw_body": raw[:4000]},
                200, {})
        form = urllib.parse.parse_qs(raw, keep_blank_values=True)
        low = {k.lower(): v for k, v in form.items()}
        if u.path == "/method":
            BROWSER_STATE["method_received"] = bool(low.get("threedsmethoddata") or low.get("3dsmethoddata"))
            self._send("<html>ok</html>")
        elif u.path == "/term":
            cres = (low.get("cres") or low.get("pares") or [""])[0]
            ipg = BROWSER_STATE.get("ipg")
            if cres and ipg and not BROWSER_STATE.get("cres_sent"):
                BROWSER_STATE["cres_sent"] = True          # el ACS puede postear duplicado (§10.1.3)
                _, r = patch_3ds(self.region, REGIONS[self.region]["store"], ipg,
                                 {"acsResponse": {"cRes": cres}},
                                 "3DS %s [cRes browser]" % BROWSER_STATE.get("label"))
                BROWSER_STATE["last"] = r
            self._send("<script>location='/result'</script>")
        else:
            self._send(_page("<p>404</p>"), 404)

    def _advance(self, r):
        BROWSER_STATE["last"] = r
        BROWSER_STATE["ipg"] = r.get("ipgTransactionId") or BROWSER_STATE.get("ipg")
        ar = r.get("authenticationResponse") or {}
        if r.get("error") or r.get("transactionStatus") in ("APPROVED", "DECLINED", "VALIDATION_FAILED"):
            return self._result(r)
        mf = (ar.get("secure3dMethod") or {}).get("methodForm")
        if mf:
            # El doc (§10.1.3) exige esperar un MÍNIMO de 10 s la notificación del
            # ACS antes de resolver el methodNotificationStatus. Se hace polling y
            # recién se avanza al recibirla, o al vencer el deadline.
            return _page("<h3>Paso 3DSMethod (device fingerprint)…</h3>"
                         "<p id=s>Esperando la notificación del ACS…</p>"
                         "<div style='display:none'>%s</div>"
                         "<script>var t0=Date.now();(function p(){"
                         "fetch('/method-status').then(r=>r.json()).then(function(j){"
                         "var el=Date.now()-t0;"
                         "if(j.received&&el>=10000){location='/after-method';return}"
                         "if(el>=12000){location='/after-method';return}"
                         "document.getElementById('s').textContent="
                         "'Esperando la notificación del ACS… '+Math.round(el/1000)+'s'"
                         "+(j.received?' (recibida)':'');setTimeout(p,500)})})();</script>" % mf)
        params = ar.get("params") or {}
        if params.get("acsURL"):
            extra = ""
            # Las respuestas reales del gateway sólo traen termURL/acsURL/cReq.
            # El session data se emite únicamente si de verdad viene, y la clave
            # se busca sin distinguir mayúsculas.
            sess = session_data(params)
            if sess:
                extra = "<input type=hidden name=threeDSSessionData value='%s'>" % sess
            return _page("<h3>Redirigiendo al challenge del ACS…</h3>"
                         "<form id=f method=POST action='%s'>"
                         "<input type=hidden name=creq value='%s'>%s</form>"
                         "<script>document.getElementById('f').submit()</script>"
                         % (params["acsURL"], params["cReq"], extra))
        return self._result(r)

    def _result(self, r):
        s3 = (r.get("secure3dResponse") or {}).get("responseCode3dSecure")
        exp = BROWSER_STATE.get("expected")
        row = EV.record("3DS %s (browser)" % BROWSER_STATE.get("label", "?"), r,
                        BROWSER_STATE.get("oid"), expected=exp)
        EV.flush()
        cls = "ok" if row["Veredicto"] == "OK" else "bad"
        return _page("<h2 class=%s>%s — %s</h2>"
                     "<p>orderId=<code>%s</code> ipgTransactionId=<code>%s</code></p>"
                     "<p>responseCode3dSecure = <b>%s</b> (esperado <b>%s</b>)</p>"
                     "<pre>%s</pre><p><a href='/'>&larr; menú</a></p>"
                     % (cls, row["Veredicto"], row["Estado"], row["OrderID"], row["ipgTransactionId"],
                        s3 or "-", exp or "-", json.dumps(r, indent=2, ensure_ascii=False)))

def serve(region="ar", port=8099):
    BrowserHandler.region = region
    BrowserHandler.port = port
    print("Fiserv homologación — modo browser (region=%s tienda=%s)"
          % (region, REGIONS[region]["store"]))
    print("Abrí:  %shttp://localhost:%d%s   (Ctrl+C para cortar)" % (CYA, port, RST))
    print("Evidencia: %s" % EV.dir)
    try:
        ThreadingHTTPServer(("127.0.0.1", port), BrowserHandler).serve_forever()
    except KeyboardInterrupt:
        print()
        EV.summary()

# ============================== CHECK / CLI ==================================
def cmd_check():
    print("URL: %s" % URL)
    try:
        req = urllib.request.Request(URL + "/payments", method="GET")
        urllib.request.urlopen(req, timeout=15)
        print("Conectividad: %sOK%s" % (GRN, RST))
    except urllib.error.HTTPError as e:
        print("Conectividad: %sOK%s (http=%d, 401 esperado sin firma)" % (GRN, RST, e.code))
    except Exception as e:
        print("Conectividad: %sFALLA%s (%s)" % (RED, RST, e))
        return 1
    for r, c in REGIONS.items():
        if not (c["key"] and c["secret"]):
            print("  %s %s: %ssin credenciales%s (poné %s_KEY/%s_SECRET en "
                  "fiserv_homologacion_secrets/creds.env)"
                  % (RED + "✗" + RST, r.upper(), YEL, RST, r.upper(), r.upper()))
            continue
        # ping firmado real: un inquiry de un id inexistente valida la firma
        st, resp = api(r, "GET", "/payments/0?storeId=%s" % c["store"])
        err = (resp.get("error") or {}).get("code", "")
        firma_ok = st != 401 and "UNAUTHENTICATED" not in str(err).upper()
        print("  %s %s: tienda %s, moneda %s — firma %s"
              % (GRN + "✓" + RST if firma_ok else RED + "✗" + RST, r.upper(), c["store"], c["currency"],
                 "OK" if firma_ok else "RECHAZADA (%s %s)" % (st, err)))
    print("  Tiendas de token: GW=%s  MTRG=%s" % (AR_STORE_TOKEN_GW, AR_STORE_TOKEN_MTRG))
    if len(NETTOKEN_CRYPTOGRAM) < 20:
        print("  %s⚠ NETTOKEN_CRYPTOGRAM tiene menos de 20 caracteres; el gateway lo rechaza.%s" % (YEL, RST))
    return 0

def cmd_report():
    base = os.path.join(SELFDIR, "fiserv_homologacion_logs")
    if not os.path.isdir(base):
        print("No hay corridas todavía.")
        return 1
    # La más reciente por mtime que efectivamente tenga planilla (las corridas
    # interrumpidas o de sondeo no la generan).
    planillas = [os.path.join(base, d, "planilla.md") for d in os.listdir(base)]
    planillas = sorted((p for p in planillas if os.path.exists(p)),
                       key=os.path.getmtime, reverse=True)
    if not planillas:
        print("No hay ninguna corrida con planilla todavía.")
        return 1
    print(open(planillas[0]).read())
    return 0

HELP = __doc__ or ""

def main():
    global EV
    args = sys.argv[1:]
    cmd = args[0] if args else "help"

    if cmd == "help" or cmd not in ("check", "ar-basic", "ar-token", "ar-3ds", "ar-3ds-alt",
                                    "ar-diag", "uy-basic", "all", "serve", "report"):
        with open(__file__) as fh:
            for i, line in enumerate(fh):
                if i < 2:
                    continue
                if not line.startswith("#"):
                    break
                print(line[2:].rstrip())
        return 0
    if cmd == "report":
        return cmd_report()

    EV = Evidence()
    if cmd == "check":
        return cmd_check()
    if cmd == "serve":
        port = int(args[1]) if len(args) > 1 and args[1].isdigit() else 8099
        region = next((a for a in args[1:] if a in REGIONS), "ar")
        return serve(region, port)

    require_creds("uy" if cmd == "uy-basic" else "ar", *(["uy"] if cmd == "all" else []))
    try:
        if cmd == "ar-basic":
            run_basic("ar")
        elif cmd == "ar-token":
            run_token()
        elif cmd == "ar-3ds":
            run_3ds("ar")
        elif cmd == "ar-3ds-alt":
            run_3ds("ar", CARDS_3DS_ALT, "3DS — tarjetas alternativas de la guía")
        elif cmd == "ar-diag":
            run_diag("ar")
        elif cmd == "uy-basic":
            run_basic("uy")
        elif cmd == "all":
            run_basic("ar")
            run_token()
            run_3ds("ar")
            run_3ds("ar", CARDS_3DS_ALT, "3DS — tarjetas alternativas de la guía")
            run_diag("ar")
            run_basic("uy")
    except KeyboardInterrupt:
        print("\n(interrumpido)")
    return 1 if EV.summary() else 0

if __name__ == "__main__":
    sys.exit(main())
