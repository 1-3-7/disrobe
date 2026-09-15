from __future__ import annotations

from typing import Any, Literal, TypedDict, Union

class CodeRange(TypedDict, total=False):
    end_rva: int
    start_rva: int

class ManagedSignatureBody(TypedDict, total=False):
    pseudo_c: str
    signature_source: Literal["managed"]
    status: Literal["recovered"]

MetadataStatus = Union[Literal["NotPresent", "Recovered"], UnsupportedVersionStatus, RejectedStatus]

MethodBody = Union[ManagedSignatureBody, RegisterSignatureBody, RefusedBody]

class MethodEntry(TypedDict, total=False):
    body: MethodBody
    code_range: CodeRange
    declaring_type: None | str
    declaring_types: list[str]
    entrypoint_rva: int
    name: str
    record_offset: int
    signature: Union[MethodSignature, None]

class MethodSignature(TypedDict, total=False):
    calling_convention: int
    generic_parameter_count: int
    parameter_types: list[TypeSignature]
    record_offset: int
    return_type: TypeSignature
    vararg_parameter_types: list[TypeSignature]

class RefusedBody(TypedDict, total=False):
    reason: str
    status: Literal["refused"]

class RegisterSignatureBody(TypedDict, total=False):
    pseudo_c: str
    signature_abstention: Literal["absent-managed-signature", "unsupported-calling-convention", "explicit-this", "generic-signature", "vararg-signature", "argument-positions-exceeded", "type-signature-kind-unsupported", "type-record-absent", "type-namespace-not-system", "type-outside-primitive-table", "non-microsoft-x64-recovery", "hidden-struct-return", "return-class-disagreement", "argument-count-disagreement", "argument-register-disagreement", "floating-point-register-disagreement", "unobserved-argument-position", "vector-argument-binding", "prototype-not-isolated", "argument-binding-not-isolated", "return-statement-not-isolated", "shared-code-range", "allocation-failed"]
    signature_source: Literal["registers"]
    status: Literal["recovered"]

class RejectedStatus(TypedDict, total=False):
    Rejected: dict[str, Any]

class SignatureSourceCounts(TypedDict, total=False):
    managed: int
    registers: int

class TypeEntry(TypedDict, total=False):
    method_record_offsets: list[int]
    qualified_name: str
    record_offset: int

class TypeSignature(TypedDict, total=False):
    kind: Literal["definition", "reference", "specification", "modified"]
    record_offset: int

class UnsupportedVersionStatus(TypedDict, total=False):
    UnsupportedVersion: dict[str, Any]

class NativeAotSymbols(TypedDict, total=False):
    metadata_status: MetadataStatus
    methods: list[MethodEntry]
    runtime: Literal["net7", "net8", "net9", "net10", "unknown"]
    schema: Literal["disrobe.dotnet.native-aot-symbols/v1"]
    signature_source_counts: SignatureSourceCounts
    types: list[TypeEntry]

