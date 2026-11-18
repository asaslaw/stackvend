"""
Project Castor: Shared Firestore Query AST Scanner & Composite Index Engine
Analyzes Python source files for Firestore compound query patterns and
extracts required composite index specifications for automated Terraform provisioning.
"""

import ast
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("castor.firestore_scanner")


@dataclass(frozen=True)
class FirestoreFieldSpec:
    field_path: str
    mode: str = "ORDER"  # "ORDER" or "ARRAY"
    order: str = "ASCENDING"  # "ASCENDING", "DESCENDING", or "CONTAINS"

    def to_dict(self) -> Dict[str, str]:
        if self.mode == "ARRAY":
            return {"field_path": self.field_path, "array_config": "CONTAINS"}
        return {"field_path": self.field_path, "order": self.order}

    def to_json_dict(self) -> Dict[str, str]:
        if self.mode == "ARRAY":
            return {"fieldPath": self.field_path, "arrayConfig": "CONTAINS"}
        return {"fieldPath": self.field_path, "order": self.order}


@dataclass
class FirestoreIndexRequirement:
    collection_id: str
    query_scope: str = "COLLECTION"  # "COLLECTION" or "COLLECTION_GROUP"
    fields: List[FirestoreFieldSpec] = field(default_factory=list)

    @property
    def signature(self) -> Tuple[str, str, Tuple[Tuple[str, str, str], ...]]:
        field_sigs = tuple((f.field_path, f.mode, f.order) for f in self.fields)
        return (self.collection_id, self.query_scope, field_sigs)


def _extract_constant_or_name(node: Optional[ast.AST]) -> Optional[str]:
    """Helper to extract string literal, constant, or identifier from an AST node."""
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if hasattr(ast, "Str") and isinstance(node, ast.Str):
        return node.s
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


class FirestoreASTVisitor(ast.NodeVisitor):
    """
    Traverses Python AST to locate Firestore queries across methods:
    .collection(), .collection_group(), .where(), .filter(), and .order_by().
    """

    def __init__(self):
        self.requirements: List[FirestoreIndexRequirement] = []
        self._visited_calls: Set[int] = set()

    def visit_Call(self, node: ast.Call):
        # Prevent analyzing sub-calls already handled as part of a parent method chain
        if id(node) in self._visited_calls:
            self.generic_visit(node)
            return

        # Unwind potential method chaining from outermost Call to innermost Call
        chain: List[Tuple[str, List[ast.expr], List[ast.keyword]]] = []
        call_nodes: List[ast.Call] = []
        curr = node

        while isinstance(curr, ast.Call) and isinstance(curr.func, ast.Attribute):
            call_nodes.append(curr)
            chain.append((curr.func.attr, curr.args, curr.keywords))
            curr = curr.func.value

        # Check if the chain begins at a collection or collection_group call
        collection_idx = -1
        for idx, (attr_name, _, _) in enumerate(chain):
            if attr_name in ("collection", "collection_group"):
                collection_idx = idx
                break

        if collection_idx != -1:
            # Mark all calls in this chain as visited
            for cn in call_nodes:
                self._visited_calls.add(id(cn))

            # Reverse the sub-chain from collection() outward to the terminal call
            relevant_chain = list(reversed(chain[: collection_idx + 1]))
            self._analyze_chain(relevant_chain)

        self.generic_visit(node)

    def _analyze_chain(self, chain: List[Tuple[str, List[ast.expr], List[ast.keyword]]]):
        """Analyzes an unwound Firestore query chain and extracts composite index requirements if needed."""
        root_method, root_args, _ = chain[0]
        query_scope = "COLLECTION_GROUP" if root_method == "collection_group" else "COLLECTION"

        collection_id = "default"
        if root_args:
            extracted_name = _extract_constant_or_name(root_args[0])
            if extracted_name:
                collection_id = extracted_name

        filters: List[Tuple[str, str]] = []  # (field_path, op_string)
        orders: List[Tuple[str, str]] = []   # (field_path, direction)

        for method_name, args, keywords in chain[1:]:
            if method_name in ("where", "filter"):
                extracted = self._parse_filter_call(method_name, args, keywords)
                if extracted:
                    filters.extend(extracted)
            elif method_name == "order_by":
                extracted_order = self._parse_order_by_call(args, keywords)
                if extracted_order:
                    orders.append(extracted_order)

        if not filters and not orders:
            return

        if self._requires_composite_index(filters, orders):
            req = self._build_index_requirement(collection_id, query_scope, filters, orders)
            if req and req.fields:
                self.requirements.append(req)

    def _parse_filter_call(
        self, method_name: str, args: List[ast.expr], keywords: List[ast.keyword]
    ) -> List[Tuple[str, str]]:
        """Extracts (field_path, op_string) from positional or FieldFilter calls."""
        res: List[Tuple[str, str]] = []

        # 1. Check keyword arguments: where(filter=FieldFilter("status", "==", "x"))
        for kw in keywords:
            if kw.arg == "filter" and isinstance(kw.value, ast.Call):
                filter_call = kw.value
                if len(filter_call.args) >= 2:
                    f_name = _extract_constant_or_name(filter_call.args[0])
                    op = _extract_constant_or_name(filter_call.args[1])
                    if f_name and op:
                        res.append((f_name, op.strip()))
                return res

        # 2. Check direct .filter(FieldFilter(...)) call
        if method_name == "filter" and args and isinstance(args[0], ast.Call):
            filter_call = args[0]
            if len(filter_call.args) >= 2:
                f_name = _extract_constant_or_name(filter_call.args[0])
                op = _extract_constant_or_name(filter_call.args[1])
                if f_name and op:
                    res.append((f_name, op.strip()))
            return res

        # 3. Check standard positional: where("field", "==", "value") or filter("field", "==", "value")
        if len(args) >= 2:
            f_name = _extract_constant_or_name(args[0])
            op = _extract_constant_or_name(args[1])
            if f_name and op:
                res.append((f_name, op.strip()))

        return res

    def _parse_order_by_call(
        self, args: List[ast.expr], keywords: List[ast.keyword]
    ) -> Optional[Tuple[str, str]]:
        """Extracts (field_path, direction) from an order_by() call."""
        if not args:
            return None

        field_name = _extract_constant_or_name(args[0])
        if not field_name:
            return None

        direction = "ASCENDING"

        # Check positional direction: order_by("ts", "DESCENDING")
        if len(args) >= 2:
            dir_val = _extract_constant_or_name(args[1])
            if dir_val and "DESC" in dir_val.upper():
                direction = "DESCENDING"
            elif dir_val and "ASC" in dir_val.upper():
                direction = "ASCENDING"

        # Check keyword direction: order_by("ts", direction="DESCENDING")
        for kw in keywords:
            if kw.arg == "direction":
                dir_val = _extract_constant_or_name(kw.value)
                if dir_val and "DESC" in dir_val.upper():
                    direction = "DESCENDING"
                elif dir_val and "ASC" in dir_val.upper():
                    direction = "ASCENDING"

        return (field_name, direction)

    def _requires_composite_index(
        self, filters: List[Tuple[str, str]], orders: List[Tuple[str, str]]
    ) -> bool:
        """
        Determines whether the query combination strictly requires a Firestore composite index.
        Firestore Rule Summary:
        - Single equality / single inequality / single order_by: NO composite index required.
        - Multiple equalities: NO composite index (Firestore zigzag merge applies).
        - Equality + Inequality on a different field: YES.
        - Equality + OrderBy on a different field: YES.
        - Multiple OrderBy on different fields: YES.
        - Array filter + OrderBy or other filter: YES.
        - Multiple Inequalities on different fields: YES.
        """
        eq_fields = [f[0] for f in filters if f[1] in ("==", "in")]
        ineq_fields = [f[0] for f in filters if f[1] in (">", ">=", "<", "<=", "!=", "not-in")]
        arr_fields = [f[0] for f in filters if f[1] in ("array_contains", "array_contains_any")]
        order_fields = [o[0] for o in orders]

        unique_eq = set(eq_fields)
        unique_ineq = set(ineq_fields)
        unique_arr = set(arr_fields)
        unique_order = set(order_fields)

        # 1. Equality + Inequality on different field
        if unique_eq and (unique_ineq - unique_eq):
            return True

        # 2. Equality + OrderBy on different field
        if unique_eq and (unique_order - unique_eq):
            return True

        # 3. Multiple OrderBy on different fields
        if len(unique_order) > 1:
            return True

        # 4. Array filter + OrderBy or other filter
        if unique_arr and (unique_order or (unique_eq - unique_arr) or (unique_ineq - unique_arr)):
            return True

        # 5. Multiple Inequality filters on different fields
        if len(unique_ineq) > 1:
            return True

        return False

    def _build_index_requirement(
        self,
        collection_id: str,
        query_scope: str,
        filters: List[Tuple[str, str]],
        orders: List[Tuple[str, str]],
    ) -> FirestoreIndexRequirement:
        """
        Builds the structured FirestoreIndexRequirement according to canonical Firestore ordering rules:
        1. Equality fields first (ASCENDING).
        2. Array field (CONTAINS).
        3. OrderBy fields (as specified).
        4. Inequality fields not already covered.
        """
        field_specs: List[FirestoreFieldSpec] = []
        seen_paths: Set[str] = set()

        # 1. Equality fields
        for field_path, op in filters:
            if op in ("==", "in") and field_path not in seen_paths:
                field_specs.append(FirestoreFieldSpec(field_path=field_path, mode="ORDER", order="ASCENDING"))
                seen_paths.add(field_path)

        # 2. Array fields
        for field_path, op in filters:
            if op in ("array_contains", "array_contains_any") and field_path not in seen_paths:
                field_specs.append(FirestoreFieldSpec(field_path=field_path, mode="ARRAY", order="CONTAINS"))
                seen_paths.add(field_path)

        # 3. OrderBy fields
        for field_path, direction in orders:
            if field_path not in seen_paths:
                field_specs.append(FirestoreFieldSpec(field_path=field_path, mode="ORDER", order=direction))
                seen_paths.add(field_path)

        # 4. Inequality fields not already present in order_by
        for field_path, op in filters:
            if op in (">", ">=", "<", "<=", "!=", "not-in") and field_path not in seen_paths:
                field_specs.append(FirestoreFieldSpec(field_path=field_path, mode="ORDER", order="ASCENDING"))
                seen_paths.add(field_path)

        return FirestoreIndexRequirement(
            collection_id=collection_id,
            query_scope=query_scope,
            fields=field_specs,
        )


def scan_firestore_queries_in_code(code: str) -> List[FirestoreIndexRequirement]:
    """Scans Python source code string for Firestore queries requiring composite indexes."""
    if not code or ("collection" not in code and "where" not in code and "filter" not in code):
        return []

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        logger.warning(f"AST parsing failed for Python code snippet: {e}")
        return []

    visitor = FirestoreASTVisitor()
    visitor.visit(tree)
    return visitor.requirements


def scan_firestore_queries(files: Dict[str, str]) -> List[FirestoreIndexRequirement]:
    """
    Scans a dictionary of filenames -> content for Firestore compound queries.
    Returns a deduplicated list of FirestoreIndexRequirement objects.
    """
    aggregated: List[FirestoreIndexRequirement] = []
    seen_signatures: Set[Tuple[str, str, Tuple[Tuple[str, str, str], ...]]] = set()

    for path, content in files.items():
        if not path.endswith(".py"):
            continue
        # Skip unit test files so test mocks don't generate production indexes
        if os.path.basename(path).startswith("test_") or "/tests/" in path:
            continue

        reqs = scan_firestore_queries_in_code(content)
        for req in reqs:
            sig = req.signature
            if sig not in seen_signatures:
                seen_signatures.add(sig)
                aggregated.append(req)

    return aggregated
