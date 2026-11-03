"""
Procus Secure — moteur de règles de détection au format Sigma (sous-ensemble).

Sigma est le format ouvert de règles de détection pour les journaux. Prise en charge :
  • detection : sélections (dictionnaires champ|modificateur: valeurs, listes de dictionnaires, listes de mots-clés)
  • modificateurs : contains, startswith, endswith, re, all   (comparaisons insensibles à la casse)
  • condition : and / or / not / ( ) / « 1 of sel* » / « all of sel* » / « 1 of them » / « all of them »
  • extension Procus « threshold » (au même niveau que detection) : déclenche seulement si la règle correspond
    `count` fois en `timeframe` secondes, par groupe `group_by` (ex. 5 échecs de mot de passe en 2 minutes par IP).
Non pris en charge (règle refusée explicitement, jamais ignorée en silence) : agrégations « | count() », « near »,
modificateurs base64/cidr/windash.
"""
from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from typing import Optional

import yaml

LEVEL_TO_SEVERITY = {"critical": "disaster", "high": "high", "medium": "average", "low": "warning",
                     "informational": "information"}
SUPPORTED_MODS = {"contains", "startswith", "endswith", "re", "all"}


class RuleError(ValueError):
    pass


# ───────────────────────── condition ─────────────────────────

def _tokenize(cond: str) -> list[str]:
    return re.findall(r"\(|\)|[^\s()]+", cond)


class _Parser:
    def __init__(self, tokens: list[str], names: list[str]):
        self.t, self.i, self.names = tokens, 0, names

    def peek(self):
        return self.t[self.i].lower() if self.i < len(self.t) else None

    def take(self):
        tok = self.t[self.i]; self.i += 1; return tok

    def parse(self):
        node = self.or_()
        if self.i != len(self.t):
            raise RuleError(f"condition invalide près de « {self.t[self.i]} »")
        return node

    def or_(self):
        left = self.and_()
        while self.peek() == "or":
            self.take(); left = ("or", left, self.and_())
        return left

    def and_(self):
        left = self.not_()
        while self.peek() == "and":
            self.take(); left = ("and", left, self.not_())
        return left

    def not_(self):
        if self.peek() == "not":
            self.take(); return ("not", self.not_())
        return self.atom()

    def atom(self):
        tok = self.peek()
        if tok is None:
            raise RuleError("condition incomplète")
        if tok == "(":
            self.take(); node = self.or_()
            if self.peek() != ")":
                raise RuleError("parenthèse non fermée")
            self.take(); return node
        if tok in ("1", "all") and self.i + 2 < len(self.t) and self.t[self.i + 1].lower() == "of":
            quant = self.take().lower(); self.take(); pat = self.take()
            if pat.lower() == "them":
                sel = list(self.names)
            else:
                rx = re.compile("^" + re.escape(pat).replace(r"\*", ".*") + "$")
                sel = [n for n in self.names if rx.match(n)]
            if not sel:
                raise RuleError(f"aucune sélection ne correspond à « {pat} »")
            return ("1of" if quant == "1" else "allof", sel)
        name = self.take()
        if name not in self.names:
            raise RuleError(f"sélection inconnue dans la condition : « {name} »")
        return ("sel", name)


def _eval(node, res: dict) -> bool:
    k = node[0]
    if k == "sel":
        return res[node[1]]
    if k == "and":
        return _eval(node[1], res) and _eval(node[2], res)
    if k == "or":
        return _eval(node[1], res) or _eval(node[2], res)
    if k == "not":
        return not _eval(node[1], res)
    vals = [res[n] for n in node[1]]
    return any(vals) if k == "1of" else all(vals)


# ───────────────────────── sélections ─────────────────────────

def _match_value(field_val, pattern, mod: Optional[str]) -> bool:
    if pattern is None:
        return field_val is None or field_val == ""
    if field_val is None:
        return False
    fv, pv = str(field_val).lower(), str(pattern).lower()
    if mod == "contains":
        return pv in fv
    if mod == "startswith":
        return fv.startswith(pv)
    if mod == "endswith":
        return fv.endswith(pv)
    if mod == "re":
        return re.search(str(pattern), str(field_val), re.IGNORECASE) is not None
    return fv == pv


def _match_dict(sel: dict, rec: dict) -> bool:
    for key, expected in sel.items():
        field, *mods = key.split("|")
        for m in mods:
            if m not in SUPPORTED_MODS:
                raise RuleError(f"modificateur non pris en charge : « {m} »")
        want_all = "all" in mods
        mod = next((m for m in mods if m != "all"), None)
        vals = expected if isinstance(expected, list) else [expected]
        got = rec.get(field.lower())
        results = [_match_value(got, v, mod) for v in vals]
        if not (all(results) if want_all else any(results)):
            return False
    return True


def _match_selection(sel, rec: dict, message: str) -> bool:
    if isinstance(sel, dict):
        return _match_dict(sel, rec)
    if isinstance(sel, list):
        if all(isinstance(x, dict) for x in sel):
            return any(_match_dict(x, rec) for x in sel)
        return any(str(k).lower() in message.lower() for k in sel)           # mots-clés dans le message
    raise RuleError("sélection invalide (dictionnaire, liste de dictionnaires ou liste de mots-clés attendue)")


class SigmaRule:
    def __init__(self, data: dict, enabled: bool = True):
        if not isinstance(data, dict) or not data.get("title"):
            raise RuleError("règle invalide : « title » manquant")
        det = data.get("detection")
        if not isinstance(det, dict) or "condition" not in det:
            raise RuleError("règle invalide : « detection.condition » manquante")
        cond = det["condition"]
        if isinstance(cond, list):
            if len(cond) != 1:
                raise RuleError("une seule condition est prise en charge")
            cond = cond[0]
        if "|" in str(cond) or re.search(r"\bnear\b", str(cond), re.I):
            raise RuleError("conditions d'agrégation Sigma non prises en charge : utilisez « threshold »")
        self.selections = {k: v for k, v in det.items() if k not in ("condition", "timeframe")}
        if not self.selections:
            raise RuleError("aucune sélection définie")
        self.ast = _Parser(_tokenize(str(cond)), list(self.selections)).parse()
        self.title = str(data["title"])
        self.id = str(data.get("id") or re.sub(r"\W+", "_", self.title.lower()))
        self.level = str(data.get("level", "medium")).lower()
        if self.level not in LEVEL_TO_SEVERITY:
            raise RuleError(f"level invalide : {self.level}")
        self.tags = [str(t) for t in (data.get("tags") or [])]
        self.description = str(data.get("description", ""))
        self.logsource = data.get("logsource") or {}
        self.enabled = enabled
        th = data.get("threshold")
        self.threshold = None
        if th:
            try:
                self.threshold = {"count": int(th["count"]), "timeframe": int(th["timeframe"]),
                                  "group_by": [str(g).lower() for g in (th.get("group_by") or [])]}
            except (KeyError, TypeError, ValueError):
                raise RuleError("threshold invalide : count, timeframe (secondes) et group_by attendus") from None
            if self.threshold["count"] < 1 or self.threshold["timeframe"] < 1:
                raise RuleError("threshold : count et timeframe doivent être ≥ 1")
        self.severity = LEVEL_TO_SEVERITY[self.level]

    def matches(self, rec: dict, message: str) -> bool:
        res = {name: _match_selection(sel, rec, message) for name, sel in self.selections.items()}
        return _eval(self.ast, res)


def parse_rule(text: str, enabled: bool = True) -> SigmaRule:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise RuleError(f"YAML invalide : {e}") from None
    return SigmaRule(data, enabled)


class SigmaEngine:
    def __init__(self, rules: Optional[list[SigmaRule]] = None):
        self.rules = rules or []
        self._hits: dict[tuple, deque] = defaultdict(deque)
        self._cooldown: dict[tuple, float] = {}

    @classmethod
    def from_db(cls, db) -> "SigmaEngine":
        rules = []
        for r in db.fetchall("SELECT * FROM sigma_rules WHERE enabled = 1"):
            try:
                rules.append(parse_rule(r["yaml"]))
            except RuleError:
                continue
        return cls(rules)

    def evaluate(self, message: str, fields: Optional[dict] = None, now: Optional[float] = None) -> list[dict]:
        """Retourne les correspondances [{'rule', 'count'}] (seuils pris en compte)."""
        now = now if now is not None else time.time()
        rec = {str(k).lower(): v for k, v in (fields or {}).items()}
        rec.setdefault("message", message)
        out = []
        for rule in self.rules:
            if not rule.matches(rec, message):
                continue
            if not rule.threshold:
                out.append({"rule": rule, "count": 1})
                continue
            th = rule.threshold
            key = (rule.id, tuple(str(rec.get(g, "")) for g in th["group_by"]))
            dq = self._hits[key]
            dq.append(now)
            while dq and now - dq[0] > th["timeframe"]:
                dq.popleft()
            last = self._cooldown.get(key)
            if len(dq) >= th["count"] and (last is None or now - last > th["timeframe"]):
                self._cooldown[key] = now
                out.append({"rule": rule, "count": len(dq), "group": key[1]})
        return out


# ───────────────────────── règles livrées ─────────────────────────

BUILTIN_RULES = [
"""
title: Force brute SSH (mots de passe refusés)
id: procus_ssh_bruteforce
level: high
description: Au moins 5 échecs de mot de passe SSH depuis la même adresse en 2 minutes.
tags: [attack.credential_access, attack.t1110.001]
detection:
  selection:
    message|contains: Failed password
  condition: selection
threshold: {count: 5, timeframe: 120, group_by: [src_ip]}
""",
"""
title: Balayage de comptes SSH (utilisateurs inexistants)
id: procus_ssh_invalid_user
level: medium
tags: [attack.credential_access, attack.t1110]
detection:
  selection:
    message|contains: Invalid user
  condition: selection
threshold: {count: 5, timeframe: 300, group_by: [src_ip]}
""",
"""
title: Connexion SSH réussie en tant que root
id: procus_ssh_root_login
level: high
tags: [attack.initial_access, attack.t1078]
detection:
  selection:
    message|contains|all: [Accepted, 'for root']
  condition: selection
""",
"""
title: Échec d'authentification sudo
id: procus_sudo_failure
level: medium
tags: [attack.privilege_escalation, attack.t1548.003]
detection:
  selection:
    message|contains|all: [sudo, authentication failure]
  condition: selection
""",
"""
title: Création d'un compte utilisateur Linux
id: procus_linux_user_created
level: medium
tags: [attack.persistence, attack.t1136.001]
detection:
  selection:
    message|contains: ['new user:', 'useradd[']
  condition: selection
""",
"""
title: Force brute Windows (échecs de connexion 4625)
id: procus_win_bruteforce
level: high
tags: [attack.credential_access, attack.t1110]
detection:
  selection:
    EventID: 4625
  condition: selection
threshold: {count: 5, timeframe: 120, group_by: [IpAddress]}
""",
"""
title: Journal d'événements Windows effacé
id: procus_win_log_cleared
level: high
tags: [attack.defense_evasion, attack.t1070.001]
detection:
  selection:
    EventID: [1102, 104]
  condition: selection
""",
"""
title: Création d'un compte local Windows
id: procus_win_user_created
level: medium
tags: [attack.persistence, attack.t1136.001]
detection:
  selection:
    EventID: 4720
  condition: selection
""",
"""
title: Ajout à un groupe d'administrateurs Windows
id: procus_win_admin_group_add
level: high
tags: [attack.persistence, attack.privilege_escalation, attack.t1098]
detection:
  event:
    EventID: [4728, 4732, 4756]
  group:
    TargetUserName|contains: [admin, administrateur]
  condition: event and group
""",
"""
title: Échecs de connexion sur un équipement Cisco
id: procus_cisco_login_failed
level: medium
tags: [attack.credential_access, attack.t1110]
detection:
  selection:
    message|contains: '%SEC_LOGIN-4-LOGIN_FAILED'
  condition: selection
threshold: {count: 3, timeframe: 300, group_by: [src_ip]}
""",
"""
title: Configuration modifiée sur un équipement Cisco
id: procus_cisco_config_changed
level: low
tags: [config_change]
detection:
  selection:
    message|contains: '%SYS-5-CONFIG_I'
  condition: selection
""",
]


def seed_builtin_rules(db):
    """Insère les règles livrées absentes (n'écrase jamais une règle modifiée ni ne réactive une règle désactivée)."""
    for text in BUILTIN_RULES:
        rule = parse_rule(text)
        db.execute("INSERT OR IGNORE INTO sigma_rules (rule_id, title, level, enabled, builtin, yaml) "
                   "VALUES (?, ?, ?, 1, 1, ?)", (rule.id, rule.title, rule.level, text.strip()))
