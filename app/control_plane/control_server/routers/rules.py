"""Rule registry, immutable versioning, validate, and test APIs."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from ..audit import log_audit_event
from ..auth import RequestContext
from ..db import get_db
from ..deps import settings
from ..models.rule import Rule, RuleVersion
from ..rbac import require_viewer, require_analyst, require_operator

router = APIRouter(prefix="/api/v1/rules", tags=["rules"])


# -- Request / Response Schemas ------------------------------------------------

class CreateRuleRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=128, example="detect_suspicious_pty")
    description: Optional[str] = Field(None, example="Detect interactive pty allocation under webserver processes")
    content: str = Field(..., min_length=5, example="rule detect_pty { from process where comm == \"python\" }")
    changelog: Optional[str] = Field(default="Initial rule version")


class CreateRuleVersionRequest(BaseModel):
    content: str = Field(..., min_length=5)
    changelog: Optional[str] = Field(default="Updated rule logic")


class ValidateRuleRequest(BaseModel):
    content: str = Field(...)


class DiagnosticItem(BaseModel):
    severity: str  # "error", "warning", "info"
    code: str
    message: str
    line: Optional[int] = None
    column: Optional[int] = None


class ValidateRuleResponse(BaseModel):
    valid: bool
    diagnostics: List[DiagnosticItem]
    ast: Optional[Dict[str, Any]] = None
    compiled_ir: Optional[Dict[str, Any]] = None


class RuleTestFixture(BaseModel):
    event_type: str = Field(..., example="process_exec")
    pid: int = Field(default=1001)
    comm: str = Field(default="bash")
    filename: Optional[str] = Field(default="/bin/bash")
    net_dst_ip: Optional[str] = None
    net_dst_port: Optional[int] = None
    attrs: Dict[str, str] = Field(default_factory=dict)


class TestRuleRequest(BaseModel):
    content: str = Field(...)
    fixtures: List[RuleTestFixture] = Field(default_factory=list)


class TestRuleResponse(BaseModel):
    matched: bool
    match_count: int
    diagnostics: List[DiagnosticItem]
    matches: List[Dict[str, Any]]


class RuleVersionResponse(BaseModel):
    id: str
    rule_id: str
    version: int
    content: str
    content_hash: str
    author: str
    changelog: Optional[str]
    compiled_ir: Optional[Dict[str, Any]]
    diagnostics: List[Dict[str, Any]]
    created_at: Optional[str]


class RuleResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    description: Optional[str]
    owner: str
    created_at: Optional[str]
    updated_at: Optional[str]
    version_count: int
    latest_version: Optional[RuleVersionResponse]


# -- Helper function to execute oilc CLI for compilation/validation ----------

def compile_oil_source(content: str) -> Dict[str, Any]:
    """Invoke oilc compiler on source string and return result envelope."""
    manifest_path = Path(settings.oilc_manifest_path)
    if not manifest_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Compiler manifest not found at {manifest_path}",
        )

    with tempfile.NamedTemporaryFile("w", suffix=".oil", delete=False) as tf:
        tf.write(content)
        tf_path = Path(tf.name)

    try:
        cmd = [
            "cargo",
            "run",
            "--manifest-path",
            str(manifest_path),
            "--quiet",
            "--",
            "compile",
            str(tf_path),
            "--format",
            "json",
        ]
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=settings.compiler_timeout_s,
        )
    except subprocess.TimeoutExpired as exc:
        tf_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="oilc compilation timed out",
        ) from exc
    finally:
        tf_path.unlink(missing_ok=True)

    if proc.returncode != 0:
        err_msg = proc.stderr.strip() or proc.stdout.strip() or "Compilation failed"
        return {
            "valid": False,
            "diagnostics": [
                {
                    "severity": "error",
                    "code": "COMPILER_ERROR",
                    "message": err_msg,
                    "line": 1,
                    "column": 1,
                }
            ],
            "compiled_ir": None,
        }

    try:
        ir_data = json.loads(proc.stdout)
        return {
            "valid": True,
            "diagnostics": [],
            "compiled_ir": ir_data,
        }
    except json.JSONDecodeError as exc:
        return {
            "valid": False,
            "diagnostics": [
                {
                    "severity": "error",
                    "code": "JSON_PARSE_ERROR",
                    "message": f"Failed to parse compiler output: {proc.stdout[:200]}",
                    "line": 1,
                    "column": 1,
                }
            ],
            "compiled_ir": None,
        }


# -- Endpoints -----------------------------------------------------------------

@router.post("", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    req: CreateRuleRequest,
    ctx: RequestContext = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> RuleResponse:
    """Create a new rule and its initial immutable version 1."""
    # Check duplicate rule name within tenant
    existing = db.scalars(
        select(Rule).where(Rule.tenant_id == ctx.tenant_id, Rule.name == req.name)
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Rule with name '{req.name}' already exists in tenant '{ctx.tenant_id}'",
        )

    # Compile source
    comp_res = compile_oil_source(req.content)

    rule = Rule(
        tenant_id=ctx.tenant_id,
        name=req.name,
        description=req.description,
        owner=ctx.user_id,
    )
    db.add(rule)
    db.flush()

    content_hash = RuleVersion.compute_hash(req.content)
    version = RuleVersion(
        rule_id=rule.id,
        version=1,
        content=req.content,
        content_hash=content_hash,
        author=ctx.user_id,
        changelog=req.changelog,
        compiled_ir=comp_res.get("compiled_ir"),
        diagnostics=comp_res.get("diagnostics"),
    )
    db.add(version)
    db.commit()
    db.refresh(rule)

    log_audit_event(
        db,
        ctx,
        action="rule.create",
        target=f"rule:{rule.id}",
        details={"name": req.name, "version": 1, "valid": comp_res.get("valid")},
    )

    return RuleResponse(**rule.to_dict())


@router.get("", response_model=List[RuleResponse])
async def list_rules(
    ctx: RequestContext = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> List[RuleResponse]:
    """List all rules for the caller's tenant."""
    rules = db.scalars(
        select(Rule).where(Rule.tenant_id == ctx.tenant_id).order_by(Rule.updated_at.desc())
    ).all()
    return [RuleResponse(**r.to_dict()) for r in rules]


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(
    rule_id: str,
    ctx: RequestContext = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> RuleResponse:
    """Get rule metadata and version details by ID."""
    rule = db.scalars(
        select(Rule).where(Rule.id == rule_id, Rule.tenant_id == ctx.tenant_id)
    ).first()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule '{rule_id}' not found",
        )
    return RuleResponse(**rule.to_dict())


@router.post("/{rule_id}/versions", response_model=RuleVersionResponse, status_code=status.HTTP_201_CREATED)
async def create_rule_version(
    rule_id: str,
    req: CreateRuleVersionRequest,
    ctx: RequestContext = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> RuleVersionResponse:
    """Create a new immutable version for an existing rule."""
    rule = db.scalars(
        select(Rule).where(Rule.id == rule_id, Rule.tenant_id == ctx.tenant_id)
    ).first()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule '{rule_id}' not found",
        )

    next_ver_num = len(rule.versions) + 1
    comp_res = compile_oil_source(req.content)
    content_hash = RuleVersion.compute_hash(req.content)

    new_ver = RuleVersion(
        rule_id=rule.id,
        version=next_ver_num,
        content=req.content,
        content_hash=content_hash,
        author=ctx.user_id,
        changelog=req.changelog,
        compiled_ir=comp_res.get("compiled_ir"),
        diagnostics=comp_res.get("diagnostics"),
    )
    db.add(new_ver)
    rule.updated_at = func.now()
    db.commit()
    db.refresh(new_ver)

    log_audit_event(
        db,
        ctx,
        action="rule.version_create",
        target=f"rule:{rule.id}:v{next_ver_num}",
        details={"version": next_ver_num, "hash": content_hash, "valid": comp_res.get("valid")},
    )

    return RuleVersionResponse(**new_ver.to_dict())


@router.get("/{rule_id}/versions/{version}", response_model=RuleVersionResponse)
async def get_rule_version(
    rule_id: str,
    version: int,
    ctx: RequestContext = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> RuleVersionResponse:
    """Get a specific version of a rule by version number."""
    rule = db.scalars(
        select(Rule).where(Rule.id == rule_id, Rule.tenant_id == ctx.tenant_id)
    ).first()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule '{rule_id}' not found",
        )

    ver = db.scalars(
        select(RuleVersion).where(RuleVersion.rule_id == rule_id, RuleVersion.version == version)
    ).first()
    if not ver:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule version v{version} not found",
        )

    return RuleVersionResponse(**ver.to_dict())


@router.post("/validate", response_model=ValidateRuleResponse)
async def validate_rule(
    req: ValidateRuleRequest,
    ctx: RequestContext = Depends(require_analyst),
) -> ValidateRuleResponse:
    """Validate OIL rule content against the compiler without persisting."""
    comp_res = compile_oil_source(req.content)
    diagnostics = [DiagnosticItem(**d) for d in comp_res.get("diagnostics", [])]
    return ValidateRuleResponse(
        valid=comp_res.get("valid", False),
        diagnostics=diagnostics,
        compiled_ir=comp_res.get("compiled_ir"),
    )


@router.post("/test", response_model=TestRuleResponse)
async def test_rule(
    req: TestRuleRequest,
    ctx: RequestContext = Depends(require_analyst),
) -> TestRuleResponse:
    """Test an OIL rule against event fixtures."""
    comp_res = compile_oil_source(req.content)
    diagnostics = [DiagnosticItem(**d) for d in comp_res.get("diagnostics", [])]

    if not comp_res.get("valid"):
        return TestRuleResponse(
            matched=False,
            match_count=0,
            diagnostics=diagnostics,
            matches=[],
        )

    # Simple fixture evaluation check for testing pipeline API
    matches = []
    for idx, fx in enumerate(req.fixtures):
        # Basic demonstration matching logic based on rule string references
        if fx.comm and fx.comm in req.content:
            matches.append({
                "fixture_index": idx,
                "event_type": fx.event_type,
                "matched_rule": "test_rule",
                "risk_score": 0.85,
            })

    return TestRuleResponse(
        matched=len(matches) > 0,
        match_count=len(matches),
        diagnostics=diagnostics,
        matches=matches,
    )
