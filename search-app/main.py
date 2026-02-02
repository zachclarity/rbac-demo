"""
OpenSearch Security Demo — RBAC & Cell-Level Search Application
================================================================
Demonstrates two security enforcement models on top of OpenSearch:

  • RBAC Mode   – filters documents by classification clearance + organisation
  • Cell-Level  – adds compartmented cell membership checks + field-level masking
"""

import os
import json
import logging
import time
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from opensearchpy import OpenSearch

# ── Logging ─────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s")
logger = logging.getLogger("search-app")

# ── Configuration ───────────────────────────────────────────────────────
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
INDEX_NAME = os.getenv("INDEX_NAME", "secure-documents")

# ── FastAPI ─────────────────────────────────────────────────────────────
app = FastAPI(title="OpenSearch Security Demo", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── OpenSearch Client ───────────────────────────────────────────────────
os_client = OpenSearch(
    hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
    use_ssl=False,
    verify_certs=False,
    timeout=30,
)

# ═══════════════════════════════════════════════════════════════════════
# SECTION 1 — PYDANTIC MODELS
# ═══════════════════════════════════════════════════════════════════════

class SearchRequest(BaseModel):
    query: str = ""
    user_id: str
    mode: str = Field(pattern="^(rbac|cell)$", default="rbac")


class DocumentUpload(BaseModel):
    title: str
    content: str
    author: str = "Unknown"
    classification: str = Field(pattern="^(UNCLASSIFIED|CONFIDENTIAL|SECRET|TOP_SECRET)$")
    organization: str
    department: str = "general"
    cell_access: List[str] = ["all"]
    shared_with: List[str] = []
    source_name: str = ""
    handler_id: str = ""
    raw_intel: str = ""
    location: str = ""


class CompareRequest(BaseModel):
    query: str = ""
    user_id: str


# ═══════════════════════════════════════════════════════════════════════
# SECTION 2 — CLASSIFICATION HIERARCHY
# ═══════════════════════════════════════════════════════════════════════

CLASSIFICATION_HIERARCHY: Dict[str, int] = {
    "UNCLASSIFIED": 0,
    "CONFIDENTIAL": 1,
    "SECRET": 2,
    "TOP_SECRET": 3,
}


def allowed_classifications(clearance: str) -> List[str]:
    """Return every classification at or below the given clearance."""
    ceiling = CLASSIFICATION_HIERARCHY.get(clearance, 0)
    return [c for c, v in CLASSIFICATION_HIERARCHY.items() if v <= ceiling]


# ═══════════════════════════════════════════════════════════════════════
# SECTION 3 — DEMO USER PROFILES
# ═══════════════════════════════════════════════════════════════════════

DEMO_USERS: Dict[str, Dict[str, Any]] = {
    "alpha-admin": {
        "username": "alpha-admin",
        "name": "Director Reyes (Alpha)",
        "organization": "agency-alpha",
        "roles": ["admin"],
        "clearance": "TOP_SECRET",
        "cell_memberships": ["cell-east", "cell-west", "cell-hq", "cell-cyber"],
        "department": "leadership",
        "description": "Full access — all classifications, all cells",
    },
    "alpha-senior": {
        "username": "alpha-senior",
        "name": "Senior Analyst Kowalski (Alpha)",
        "organization": "agency-alpha",
        "roles": ["senior-analyst"],
        "clearance": "SECRET",
        "cell_memberships": ["cell-east", "cell-hq"],
        "department": "analysis",
        "description": "SECRET clearance — East & HQ cells only",
    },
    "alpha-analyst": {
        "username": "alpha-analyst",
        "name": "Analyst Park (Alpha)",
        "organization": "agency-alpha",
        "roles": ["analyst"],
        "clearance": "CONFIDENTIAL",
        "cell_memberships": ["cell-hq"],
        "department": "analysis",
        "description": "CONFIDENTIAL clearance — HQ cell only",
    },
    "alpha-viewer": {
        "username": "alpha-viewer",
        "name": "Intern Davis (Alpha)",
        "organization": "agency-alpha",
        "roles": ["viewer"],
        "clearance": "UNCLASSIFIED",
        "cell_memberships": [],
        "department": "public-affairs",
        "description": "UNCLASSIFIED only — no cell memberships",
    },
    "bravo-analyst": {
        "username": "bravo-analyst",
        "name": "Analyst Tanaka (Bravo)",
        "organization": "agency-bravo",
        "roles": ["analyst"],
        "clearance": "SECRET",
        "cell_memberships": ["cell-west"],
        "department": "field-ops",
        "description": "SECRET clearance — West cell only (federated partner)",
    },
    "bravo-viewer": {
        "username": "bravo-viewer",
        "name": "Clerk Okonkwo (Bravo)",
        "organization": "agency-bravo",
        "roles": ["viewer"],
        "clearance": "UNCLASSIFIED",
        "cell_memberships": [],
        "department": "admin",
        "description": "UNCLASSIFIED only — Bravo org (federated partner)",
    },
}


# ═══════════════════════════════════════════════════════════════════════
# SECTION 4 — SEED DOCUMENTS
# ═══════════════════════════════════════════════════════════════════════

SEED_DOCUMENTS = [
    # ── UNCLASSIFIED ────────────────────────────────────────────────
    {
        "title": "Public Affairs Monthly Summary — January",
        "content": "Community engagement events across all districts continued at expected levels. The public outreach programme received positive media coverage. No operational details included.",
        "author": "Public Affairs Office",
        "classification": "UNCLASSIFIED",
        "organization": "agency-alpha",
        "department": "public-affairs",
        "cell_access": ["all"],
        "shared_with": ["all"],
        "source_name": "",
        "handler_id": "",
        "raw_intel": "",
        "location": "All Districts",
        "date_created": "2025-01-28",
    },
    {
        "title": "Agency Bravo Quarterly Newsletter — Q4",
        "content": "Bravo operations maintained steady performance in Q4. Staff training programmes expanded to include cross-agency collaboration modules with Alpha.",
        "author": "Bravo Communications",
        "classification": "UNCLASSIFIED",
        "organization": "agency-bravo",
        "department": "communications",
        "cell_access": ["all"],
        "shared_with": ["all"],
        "source_name": "",
        "handler_id": "",
        "raw_intel": "",
        "location": "Bravo HQ",
        "date_created": "2025-01-05",
    },
    {
        "title": "Open Data Initiative — Environmental Monitoring Results",
        "content": "Sensor network data from 47 monitoring stations published under open data mandate. Air quality indices remain within acceptable ranges for all tracked regions.",
        "author": "Data Governance Team",
        "classification": "UNCLASSIFIED",
        "organization": "agency-alpha",
        "department": "data-governance",
        "cell_access": ["all"],
        "shared_with": ["all"],
        "source_name": "",
        "handler_id": "",
        "raw_intel": "",
        "location": "National",
        "date_created": "2025-01-18",
    },

    # ── CONFIDENTIAL ────────────────────────────────────────────────
    {
        "title": "Internal Resource Allocation Plan — FY26",
        "content": "Budget forecasts project a 12 % increase in technical surveillance funding. Human resources will redistribute three analyst positions from Western to Eastern district to address emerging workload.",
        "author": "Planning Division",
        "classification": "CONFIDENTIAL",
        "organization": "agency-alpha",
        "department": "planning",
        "cell_access": ["cell-hq"],
        "shared_with": [],
        "source_name": "",
        "handler_id": "",
        "raw_intel": "",
        "location": "HQ",
        "date_created": "2025-01-10",
    },
    {
        "title": "Eastern District Surveillance Summary",
        "content": "Routine electronic surveillance in the eastern corridor detected 14 new signals of interest during the reporting period. Three warrant further investigation.",
        "author": "SIGINT Team East",
        "classification": "CONFIDENTIAL",
        "organization": "agency-alpha",
        "department": "operations",
        "cell_access": ["cell-east"],
        "shared_with": [],
        "source_name": "SIGINT Collector E-12",
        "handler_id": "T-2290",
        "raw_intel": "Freq 14.225 MHz USB — intermittent encrypted burst transmissions logged 0200–0400 local.",
        "location": "Eastern District",
        "date_created": "2025-01-12",
    },
    {
        "title": "Western District Threat Assessment",
        "content": "Threat levels in the western corridor remain at ELEVATED. Cross-border movement patterns have shifted since November, suggesting new logistics routes.",
        "author": "Bravo Threat Analysis Unit",
        "classification": "CONFIDENTIAL",
        "organization": "agency-bravo",
        "department": "analysis",
        "cell_access": ["cell-west"],
        "shared_with": [],
        "source_name": "OSINT Aggregator W-3",
        "handler_id": "B-7714",
        "raw_intel": "Satellite imagery diff shows 23 new structures along grid 5521–5530 since last assessment.",
        "location": "Western District",
        "date_created": "2025-01-14",
    },
    {
        "title": "Inter-Agency Coordination Report — Joint Exercise SILVER BRIDGE",
        "content": "Alpha and Bravo successfully conducted the SILVER BRIDGE joint exercise. Communications interoperability was validated. Recommendations for improved key management attached.",
        "author": "Joint Operations Centre",
        "classification": "CONFIDENTIAL",
        "organization": "agency-alpha",
        "department": "joint-ops",
        "cell_access": ["cell-hq", "cell-west"],
        "shared_with": ["agency-bravo"],
        "source_name": "",
        "handler_id": "",
        "raw_intel": "",
        "location": "Joint Facility",
        "date_created": "2025-01-20",
    },

    # ── SECRET ──────────────────────────────────────────────────────
    {
        "title": "Operation SUNRISE — Eastern District Field Report",
        "content": "Field operatives confirm that surveillance targets have increased activity near the port facility. Pattern analysis correlates with prior threat models from Q3.",
        "author": "Field Team East",
        "classification": "SECRET",
        "organization": "agency-alpha",
        "department": "operations",
        "cell_access": ["cell-east"],
        "shared_with": [],
        "source_name": "HUMINT Source ECHO-7",
        "handler_id": "H-4472",
        "raw_intel": "Source reports face-to-face meeting observed at 0300 local, grid ref 4477-8812. Two unknown individuals. Confidence: HIGH.",
        "location": "Eastern District",
        "date_created": "2025-01-15",
    },
    {
        "title": "Cyber Threat Analysis — APT Group PHANTOM VIPER",
        "content": "PHANTOM VIPER has shifted infrastructure to new hosting providers. Malware samples recovered from honeypot HN-09 show updated C2 protocol with domain-fronting capability.",
        "author": "Cyber Threat Intel Cell",
        "classification": "SECRET",
        "organization": "agency-alpha",
        "department": "cyber",
        "cell_access": ["cell-cyber"],
        "shared_with": [],
        "source_name": "Honeypot Network HN-09",
        "handler_id": "C-1138",
        "raw_intel": "SHA-256 0xAB34…F19C — beacon interval 43 s, jitter 12 %. Exfil over DNS TXT to *.cdn-edge[.]xyz.",
        "location": "Cyber Operations Centre",
        "date_created": "2025-01-17",
    },
    {
        "title": "Joint East / HQ Intelligence Briefing — Weekly",
        "content": "Combined assessment from Eastern field teams and HQ analysts. Three priority intelligence requirements updated. Eastern district HUMINT networks are producing at above-average rates.",
        "author": "Combined Analysis Group",
        "classification": "SECRET",
        "organization": "agency-alpha",
        "department": "analysis",
        "cell_access": ["cell-east", "cell-hq"],
        "shared_with": [],
        "source_name": "Multiple (aggregated)",
        "handler_id": "CAG-EAST",
        "raw_intel": "Aggregated take: 17 HUMINT reports, 42 SIGINT intercepts, 8 OSINT items processed this cycle.",
        "location": "HQ / Eastern District",
        "date_created": "2025-01-19",
    },
    {
        "title": "Operation DUSK — Western Ops Report",
        "content": "Bravo field team reports successful deployment of sensor package along the western corridor. Initial telemetry confirms coverage of primary transit route.",
        "author": "Bravo Field Team West",
        "classification": "SECRET",
        "organization": "agency-bravo",
        "department": "operations",
        "cell_access": ["cell-west"],
        "shared_with": [],
        "source_name": "Technical Source WHISPER-4",
        "handler_id": "B-3301",
        "raw_intel": "Sensor array active — 8 nodes, mesh uplink confirmed. First vehicle detection log: 14 transits in 6 h window.",
        "location": "Western District",
        "date_created": "2025-01-21",
    },

    # ── TOP SECRET ──────────────────────────────────────────────────
    {
        "title": "Deep Cover Source Report — Eastern Network CARDINAL",
        "content": "Source CARDINAL provided critical insight into adversary command structure. Information corroborated by independent SIGINT. Details restricted to CARDINAL compartment.",
        "author": "HUMINT Operations (Restricted)",
        "classification": "TOP_SECRET",
        "organization": "agency-alpha",
        "department": "humint",
        "cell_access": ["cell-east"],
        "shared_with": [],
        "source_name": "CARDINAL (deep cover — identity NOFORN)",
        "handler_id": "RESTRICTED",
        "raw_intel": "Source confirms adversary leadership transition expected within 60 days. New commander assessed as more aggressive. Evacuation contingency CARDINAL-EXIT updated.",
        "location": "Eastern District (undisclosed)",
        "date_created": "2025-01-22",
    },
    {
        "title": "National Cyber Infrastructure Vulnerability Assessment",
        "content": "Critical vulnerabilities identified in three national infrastructure sectors. Exploitation would cause cascading failures. Remediation timeline: 90–180 days.",
        "author": "National Cyber Defence Unit",
        "classification": "TOP_SECRET",
        "organization": "agency-alpha",
        "department": "cyber",
        "cell_access": ["cell-cyber", "cell-hq"],
        "shared_with": [],
        "source_name": "Penetration Test IRON GATE (authorised)",
        "handler_id": "C-0001",
        "raw_intel": "CVE-2025-XXXX in SCADA firmware v4.2.1 — unauthenticated RCE. 1,247 exposed instances identified via Shodan. Proof-of-concept validated.",
        "location": "National",
        "date_created": "2025-01-24",
    },
]


# ═══════════════════════════════════════════════════════════════════════
# SECTION 5 — INDEX MAPPING
# ═══════════════════════════════════════════════════════════════════════

INDEX_SETTINGS = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "analysis": {
            "analyzer": {
                "content_analyzer": {
                    "type": "custom",
                    "tokenizer": "standard",
                    "filter": ["lowercase", "stop", "snowball"],
                }
            }
        },
    },
    "mappings": {
        "properties": {
            "title":          {"type": "text", "analyzer": "content_analyzer", "fields": {"keyword": {"type": "keyword"}}},
            "content":        {"type": "text", "analyzer": "content_analyzer"},
            "author":         {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "classification": {"type": "keyword"},
            "organization":   {"type": "keyword"},
            "department":     {"type": "keyword"},
            "cell_access":    {"type": "keyword"},
            "shared_with":    {"type": "keyword"},
            "source_name":    {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "handler_id":     {"type": "keyword"},
            "raw_intel":      {"type": "text"},
            "location":       {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "date_created":   {"type": "date", "format": "yyyy-MM-dd"},
        }
    },
}


# ═══════════════════════════════════════════════════════════════════════
# SECTION 6 — SECURITY FILTER BUILDERS
# ═══════════════════════════════════════════════════════════════════════

def _text_query(search_text: str) -> dict:
    """Full-text portion of the query (or match_all when blank)."""
    if search_text.strip():
        return {
            "multi_match": {
                "query": search_text,
                "fields": ["title^3", "content^2", "author", "department", "location", "source_name", "raw_intel"],
                "fuzziness": "AUTO",
            }
        }
    return {"match_all": {}}


def _org_filter(org: str) -> dict:
    """Allow documents from the user's org, or explicitly shared with them, or shared with 'all'."""
    return {
        "bool": {
            "should": [
                {"term": {"organization": org}},
                {"term": {"shared_with": org}},
                {"term": {"shared_with": "all"}},
            ],
            "minimum_should_match": 1,
        }
    }


def build_rbac_query(search_text: str, user: dict) -> dict:
    """
    RBAC MODE
    ─────────
    • Classification filter — user sees only docs at or below their clearance
    • Organisation filter  — user sees only their org's docs + explicitly shared docs
    """
    return {
        "bool": {
            "must": [_text_query(search_text)],
            "filter": [
                {"terms": {"classification": allowed_classifications(user["clearance"])}},
                _org_filter(user["organization"]),
            ],
        }
    }


def build_cell_query(search_text: str, user: dict) -> dict:
    """
    CELL-LEVEL MODE
    ────────────────
    • All RBAC filters PLUS
    • Cell-access filter — document's cell_access must overlap with user's cell_memberships
      (documents tagged 'all' are visible to everyone in the org)
    """
    cells = user.get("cell_memberships", [])

    cell_should = [{"term": {"cell_access": "all"}}]
    if cells:
        cell_should.append({"terms": {"cell_access": cells}})

    return {
        "bool": {
            "must": [_text_query(search_text)],
            "filter": [
                {"terms": {"classification": allowed_classifications(user["clearance"])}},
                _org_filter(user["organization"]),
                {"bool": {"should": cell_should, "minimum_should_match": 1}},
            ],
        }
    }


SENSITIVE_FIELDS = ["source_name", "handler_id", "raw_intel"]


def apply_field_masking(hits: list, user: dict) -> list:
    """
    Field-level masking for Cell-Level mode.
    If the user does NOT have cell membership overlapping the document's cell_access,
    sensitive fields are redacted.  Even if the document passed the query filter
    (e.g. tagged 'all'), we still mask sensitive fields unless the user is in
    at least one specific cell listed on the document.
    """
    user_cells = set(user.get("cell_memberships", []))

    for hit in hits:
        src = hit["_source"]
        doc_cells = set(src.get("cell_access", []))

        # User has specific cell overlap (ignoring the 'all' wildcard)
        specific_cells = doc_cells - {"all"}
        has_specific_access = bool(user_cells & specific_cells)

        src["_field_access"] = {}
        for field in SENSITIVE_FIELDS:
            val = src.get(field, "")
            if not val:
                src["_field_access"][field] = "empty"
                continue
            if has_specific_access:
                src["_field_access"][field] = "visible"
            else:
                src[field] = "██ REDACTED ██"
                src["_field_access"][field] = "redacted"

    return hits


# ═══════════════════════════════════════════════════════════════════════
# SECTION 7 — STARTUP (INDEX CREATION + SEED)
# ═══════════════════════════════════════════════════════════════════════

@app.on_event("startup")
def startup_event():
    # Retry until OpenSearch is reachable
    for attempt in range(40):
        try:
            info = os_client.info()
            logger.info("Connected to OpenSearch %s", info["version"]["number"])
            break
        except Exception as exc:
            logger.warning("OpenSearch not ready (attempt %d): %s", attempt + 1, exc)
            time.sleep(3)
    else:
        raise RuntimeError("Could not connect to OpenSearch after 40 attempts")

    # Create index
    if not os_client.indices.exists(INDEX_NAME):
        os_client.indices.create(INDEX_NAME, body=INDEX_SETTINGS)
        logger.info("Created index '%s'", INDEX_NAME)

        # Seed documents
        for i, doc in enumerate(SEED_DOCUMENTS):
            os_client.index(index=INDEX_NAME, id=f"seed-{i}", body=doc, refresh=False)
        os_client.indices.refresh(INDEX_NAME)
        logger.info("Seeded %d documents", len(SEED_DOCUMENTS))
    else:
        logger.info("Index '%s' already exists — skipping seed", INDEX_NAME)


# ═══════════════════════════════════════════════════════════════════════
# SECTION 8 — API ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/users")
def list_users():
    """Return all demo user profiles."""
    return DEMO_USERS


@app.get("/api/stats")
def index_stats():
    """Total document count (unfiltered)."""
    try:
        count = os_client.count(index=INDEX_NAME)["count"]
        return {"total_documents": count}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── SEARCH ──────────────────────────────────────────────────────────────

def _execute_search(query: dict, size: int = 50) -> dict:
    return os_client.search(index=INDEX_NAME, body={"query": query, "size": size, "sort": [{"date_created": "desc"}]})


def _format_hit(hit: dict) -> dict:
    doc = hit["_source"]
    doc["_id"] = hit["_id"]
    doc["_score"] = hit.get("_score")
    return doc


@app.post("/api/search")
def search_documents(req: SearchRequest):
    """Search with either RBAC or Cell-Level security mode."""
    user = DEMO_USERS.get(req.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Unknown user")

    if req.mode == "rbac":
        query = build_rbac_query(req.query, user)
        results = _execute_search(query)
        hits = [_format_hit(h) for h in results["hits"]["hits"]]
        filter_explanation = (
            f"Classification ≤ {user['clearance']}  •  "
            f"Organisation = {user['organization']} (+ shared)"
        )
    else:  # cell
        query = build_cell_query(req.query, user)
        results = _execute_search(query)
        raw_hits = results["hits"]["hits"]
        apply_field_masking(raw_hits, user)
        hits = [_format_hit(h) for h in raw_hits]
        cells_str = ", ".join(user["cell_memberships"]) if user["cell_memberships"] else "(none)"
        filter_explanation = (
            f"Classification ≤ {user['clearance']}  •  "
            f"Organisation = {user['organization']} (+ shared)  •  "
            f"Cells = {cells_str}  •  Sensitive fields masked where cell access is insufficient"
        )

    total_docs = os_client.count(index=INDEX_NAME)["count"]
    return {
        "mode": req.mode,
        "user": user,
        "query_text": req.query or "(all documents)",
        "filter_explanation": filter_explanation,
        "total_in_index": total_docs,
        "visible_count": len(hits),
        "hidden_count": total_docs - len(hits),
        "documents": hits,
    }


# ── COMPARE (side-by-side) ──────────────────────────────────────────────

@app.post("/api/compare")
def compare_modes(req: CompareRequest):
    """Run the same query in both modes and return side-by-side results."""
    user = DEMO_USERS.get(req.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Unknown user")

    # RBAC
    rbac_query = build_rbac_query(req.query, user)
    rbac_results = _execute_search(rbac_query)
    rbac_hits = [_format_hit(h) for h in rbac_results["hits"]["hits"]]

    # Cell-Level
    cell_query = build_cell_query(req.query, user)
    cell_results = _execute_search(cell_query)
    cell_raw = cell_results["hits"]["hits"]
    apply_field_masking(cell_raw, user)
    cell_hits = [_format_hit(h) for h in cell_raw]

    total = os_client.count(index=INDEX_NAME)["count"]
    return {
        "user": user,
        "query_text": req.query or "(all documents)",
        "total_in_index": total,
        "rbac": {"visible": len(rbac_hits), "documents": rbac_hits},
        "cell": {"visible": len(cell_hits), "documents": cell_hits},
    }


# ── UPLOAD ──────────────────────────────────────────────────────────────

@app.post("/api/documents")
def upload_document(doc: DocumentUpload):
    """Index a new document into OpenSearch."""
    body = doc.dict()
    body["date_created"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    result = os_client.index(index=INDEX_NAME, body=body, refresh="wait_for")
    return {"status": "indexed", "id": result["_id"]}


# ── DELETE (for demo resets) ────────────────────────────────────────────

@app.post("/api/reset")
def reset_index():
    """Delete and re-create the index with fresh seed data."""
    if os_client.indices.exists(INDEX_NAME):
        os_client.indices.delete(INDEX_NAME)
    os_client.indices.create(INDEX_NAME, body=INDEX_SETTINGS)
    for i, doc in enumerate(SEED_DOCUMENTS):
        os_client.index(index=INDEX_NAME, id=f"seed-{i}", body=doc, refresh=False)
    os_client.indices.refresh(INDEX_NAME)
    return {"status": "reset", "documents_seeded": len(SEED_DOCUMENTS)}


# ═══════════════════════════════════════════════════════════════════════
# SECTION 9 — STATIC FILES (UI)
# ═══════════════════════════════════════════════════════════════════════

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def serve_ui():
    return FileResponse("static/index.html")
