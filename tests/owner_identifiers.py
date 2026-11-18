"""FD-12 test support: detect owner-specific identifiers WITHOUT shipping them.

Each identifier is stored only as the SHA-256 of its lower-cased form (plus its length, to skip hashing tokens that
cannot match). Text is split into tokens; each token yields a few normalized candidates (the token, its `/`, `@`, `:`
separated components, the dot-suffixes of each component, each dot label and its `-` separated pieces, and adjacent
component pairs joined by `/`), and a hit is a candidate whose digest is in the table. Reports name the identifier's
key (e.g. `folder_1`), never its value.

Context rule: `owner_handle` is not a hit inside the intended public repository slug (`public_slug`): the public repo
location is an owner decision, so links to it are allowed wherever they appear.
"""
import hashlib
import re
from functools import lru_cache
from typing import Dict, Iterable, List, Optional, Set, Tuple

# key -> (sha256 of the lower-cased identifier, its length)
IDENTIFIER_DIGESTS: Dict[str, Tuple[str, int]] = {
    "owner_org": ("2bf97887d25e38ae5c0ec3b4a91abfc6449209ec0b27a0421c218ccff6e35559", 24),
    "owner_handle": ("61e659eb835eb3cc98141209b77a724f131002b69a096a123662b284eaec95be", 7),
    "private_repo": ("4ce93d4df8075cc3d1eb060002bbd64507cb7e4a47bf0aec6011d5012cd312db", 21),
    "domain_a": ("bfa36f33b5b270e99dd119ef09cd54a82d1a5cb50efed24256a6c84820ea990f", 16),
    "domain_b": ("edce21128c7add536c4ae47e1501c35b57f166bfd042bf214a65a1071bc194a8", 12),
    "home_path": ("0f9b2ea4899ba52eb8f34f861674f35dff20b547c7d7c2c1ce8664cc2d8399d1", 11),
    "folder_1": ("a9f0f4c7a9364aa26c838d9116c306811d9d3ff1056398e33471a6ef1e7799f9", 12),
    "folder_2": ("27ee82b84f04b46f38ab29e37d104bb97b07c7f7cf987daf4f591377bbfba793", 12),
    "folder_3": ("77646c584cf623a4a37d35b75962ce706e9d43ca520cbdef295e8364c88f3b3a", 12),
    "folder_4": ("45a97c6cd83e58690c5262500dfb79288b29ae2214c0e8ae7a6221f75964cffd", 12),
    "folder_5": ("a7df3cc7ecf8d9d5ee2ac7fedcd413fc565d0a0c37f08b6a0fa6813b72618f20", 12),
    "org_id": ("ea2d331b8be4cc518412d039b1535a4c7ed7d4ed3b860d1fcca94706d3385591", 12),
    "billing": ("b1e2252838a7151c014891665e2e6981d81559ab1152c6027c90a8b8a0c4a7a7", 20),
    "project_number": ("92fe1b271784682e489b9c6da40cc3f2f2b8d7b0f13298b4ce17e2be1d2f4b47", 12),
    # release-preview sweep (10-18): the two host installs (project id + number), the owner's e-mail, a second
    # billing account and a deleted child project seen in internal notes.
    "host_project_a": ("b6c3f7833cf1b4e0d6e5961ff425353575a71737ad7e794e584dff574e795f50", 13),
    "host_project_b": ("25d8a011f8ce63a8ea60ddb412607122e939cb119db0fb121f2e72c9409d4617", 10),
    "host_number_a": ("e769d1a4155a224f08790c75f0286f3d48995ff343a285df22804038d48f6178", 12),
    "host_number_b": ("9b217d339768b95fb5b94c61e331fefd9732c75e75441bd415cbef658f8e78be", 12),
    "owner_email": ("90cea617b854a2bbeb3e1c14ec697b140e6303541fadbba032ce836191f1bc39", 22),
    "billing_2": ("f410e435d2d5389b02e6252870c65cf6f531f6dcd0a5aa4d6e20db4bed364fd0", 20),
    "child_project_1": ("fb159cc0a7a0f694f71468ed5ab68ecae11df9eaa0f669515325327eb983b8e8", 14),
    "child_number_1": ("2ef6137e5f9ad755a21ec83edef0a9ceac7cc3a0779f2d15ab7a463b2c9a12ee", 12),
    "child_number_2": ("c51649d0cb441c132c88279acc535cd0b4f8bdbcc7a88a12343af9dd82671dd2", 12),
    # RC fresh install (11-03): host project id + number and its managed-workloads folder.
    "host_project_c": ("7d4c827c635661efb80e204ce113f123a26ad0e1fa056ad6fe377e21d8830aba", 11),
    "host_number_c": ("e42e3f49880b4867d61977ac6c7ed05b874f6160eb3f29fc4ee3304a1cefd0be", 12),
    "folder_6": ("bc4d40a486ad4f70d1cf92abc477422adfed8fc4428b7627b9632af4ce808595", 12),
    # pre-bootstrap live test (11-03): throwaway host project id + number and its folder.
    "host_project_d": ("c69407ed58d3e1c79ba72f38c774d8f40ddc1c3f215dd9bffe8e825b3ce362cf", 11),
    "host_number_d": ("6ceaac665608735a8deaefae46600e6adab0467e31d9975d828d9c159c80f68b", 12),
    "folder_7": ("c797209b7326d1b910c1035bb7f9277f3820765c7ce078ffc691a2134ad06093", 12),
}
PUBLIC_SLUG = ("2cca0cf0ec3a9239d92f07ee2b1a7043c178c1ae24e5ac14e28444cb20b7c36d", 17)

_BY_DIGEST = {d: k for k, (d, _n) in IDENTIFIER_DIGESTS.items()}
_LENGTHS = {n for _d, n in IDENTIFIER_DIGESTS.values()} | {PUBLIC_SLUG[1]}
_TOKEN = re.compile(r"[A-Za-z0-9@._:/+-]+")
_SPLIT = re.compile(r"[/@:]+")


@lru_cache(maxsize=1 << 16)
def _digest(s: str) -> Optional[str]:
    return hashlib.sha256(s.encode("utf-8")).hexdigest() if len(s) in _LENGTHS else None


def _candidates(token: str) -> Set[str]:
    t = token.lower().strip("._:/+-")
    parts = [p.strip("._+-") for p in _SPLIT.split(t)]
    parts = [p for p in parts if p]
    out = {t, *parts}
    for p in parts:
        bits = p.split(".")
        out.update(".".join(bits[i:]) for i in range(1, len(bits) - 1))
        # each dot label and its hyphen pieces: a project id as an e-mail host label
        # (`sa@<project>.iam.gserviceaccount.com`) and a project number inside a Cloud Run URL
        # (`<service>-<number>.<region>.run.app`)
        for label in bits:
            out.add(label)
            out.update(piece for piece in label.split("-") if piece)
    for a, b in zip(parts, parts[1:]):
        out.add(f"{a}/{b}")
        out.add(f"{a}/{b.split('.')[0]}")  # owner/repo.git
    return out


@lru_cache(maxsize=1 << 18)
def token_hits(token: str) -> frozenset:
    cands = _candidates(token)
    digests = {_digest(c) for c in cands} - {None}
    keys = {_BY_DIGEST[d] for d in digests if d in _BY_DIGEST}
    if "owner_handle" in keys and PUBLIC_SLUG[0] in digests:
        keys.discard("owner_handle")  # the intended public repo slug (owner decision), allowed everywhere
    return frozenset(keys)


def find(text: str, keys: Optional[Iterable[str]] = None) -> List[Tuple[int, str]]:
    """[(line number, identifier key)] for every hit (restricted to `keys` when given)."""
    want = set(keys) if keys is not None else None
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        for tok in _TOKEN.findall(line):
            for key in sorted(token_hits(tok)):
                if want is None or key in want:
                    hits.append((n, key))
    return hits
