# Roborun-Robotank-Arena-AI-Tank-Runner — Web3 online game platform engine.
# Single-file engine: arenas, matches, tanks, scoring, leaderboard. All config pre-populated.
#
# Addresses and hex constants below are unique to this file and are not reused from
# any other contract or code generation (Robotank.sol, BacklineLedger, Rockaf,
# HermesAI, EwAI, ThornGate, FlintLock, etc.). Use get_all_constants() or
# validate_platform_config() to inspect or verify.

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple

# -----------------------------------------------------------------------------
# Unique config: addresses and hex (not reused from any other contract/generation)
# -----------------------------------------------------------------------------
ARENA_TREASURY_ADDRESS = "0xB7e1F3a5C9d2E4f6A8b0C2d4E6f8A0b2C4d6E8f1"
PLATFORM_VAULT_ADDRESS = "0xC8f2A4b6D0e2F4a6B8c0D2e4F6a8B0c2D4e6F8a2"
REWARD_POOL_ADDRESS = "0xD9a3B5c7E1f3A5b7C9d1E3f5A7b9C1d3E5f7A9b3"
OPERATOR_CORTEX_ADDRESS = "0xE0b4C6d8F2a4B6c8D0e2F4a6B8c0D2e4F6a8B4c6"
ORACLE_NODE_ADDRESS = "0xF1c5D7e9A3b5C7d9E1f3A5b7C9d1E3f5A7b9C5d7"

ARENA_DOMAIN_SALT = "0x1a9e7c3b5d0f2e4a6c8b0d2f4a6e8c0b2d4f6a8e0"
PLATFORM_VERSION_HASH = "0x3f8b2d4e6a0c2e4f6b8d0a2c4e6f8b0d2a4c6e8f0"
CHASSIS_MINT_SALT = "0x5c2e8a1d4f7b0e3a6c9d2f5a8b1e4c7d0a3f6b9e2"
MATCHMAKING_SEED = "0x7e4a0c2d6f8b1e3a5c7d9f0b2d4e6a8c0e2f4b6d8"

MAX_PLATOON_SIZE = 28
ARENA_COOLDOWN_TICKS = 81
PHASE_DURATION_BLOCKS = 447
MAX_PHASE_INDEX = 7
BOUNTY_BASE_UNITS = 3072
TICK_MODULUS = 29
VAULT_SHARE_BPS = 80
CONTROL_SHARE_BPS = 20
MAX_ACTIVE_ARENAS = 64
MAX_MATCHES_PER_ARENA = 256
BATTERY_DRAIN_PER_TICK = 2
BATTERY_RECHARGE_AT_CHECKPOINT = 30
DEFAULT_STARTING_BATTERY = 100
MIN_BATTERY_TO_FIRE = 12
DAMAGE_PER_TURRET_FIRE = 15
SCORE_PER_CHECKPOINT = 50
SCORE_PER_KILL = 100
LEADERBOARD_TOP_N = 100
SESSION_TIMEOUT_SECONDS = 3600


class ArenaPhase(IntEnum):
    IDLE = 0
    WARMUP = 1
    ENGAGED = 2
    PEAK = 3
    CLOSURE = 4
    SETTLE = 5
    TERMINAL = 6


class MatchStatus(IntEnum):
    PENDING = 0
    ACTIVE = 1
    FINISHED = 2
    CANCELLED = 3


# -----------------------------------------------------------------------------
# Platform exceptions (unique names, not Tank*, Ledger_*, RigCue_*, etc.)
# -----------------------------------------------------------------------------
class ArenaEngineNotOperator(Exception):
    """Caller is not the operator cortex."""


class ArenaEngineArenaNotFound(Exception):
    """Arena id does not exist."""


class ArenaEngineArenaPaused(Exception):
    """Arena is paused."""


class ArenaEnginePhaseLocked(Exception):
    """Phase transition not allowed."""


class ArenaEnginePlatoonFull(Exception):
    """Platoon slot capacity reached."""


class ArenaEngineBatteryDepleted(Exception):
    """Chassis battery too low for action."""


class ArenaEngineCooldownActive(Exception):
    """Turret or action still on cooldown."""


class ArenaEngineChassisNotFound(Exception):
    """Chassis or player not registered."""


class ArenaEngineMatchNotFound(Exception):
    """Match id does not exist."""


class ArenaEngineMatchNotActive(Exception):
    """Match is not in active state."""


class ArenaEngineInvalidAmount(Exception):
    """Amount or value out of bounds."""


class ArenaEngineZeroDisallowed(Exception):
    """Zero address or zero value not allowed."""


# -----------------------------------------------------------------------------
# Data models
# -----------------------------------------------------------------------------
@dataclass
class ChassisStats:
    damage_dealt: int = 0
    battles_won: int = 0
    last_fire_tick: int = 0
    checkpoints_hit: int = 0


@dataclass
class PlatoonSlot:
    player_id: str
    enlisted_at_tick: int
    active: bool
    battery_level: int
    last_fire_tick: int


@dataclass
class ArenaRecord:
    arena_id: int
    start_tick: int
    phase: int
    terminated: bool
    bounty_claimed: int
    created_at: float


@dataclass
class MatchRecord:
    match_id: str
    arena_id: int
    status: int
    start_tick: int
    end_tick: int
    winner_player_id: Optional[str]
    participants: List[str] = field(default_factory=list)
    scores: Dict[str, int] = field(default_factory=dict)


@dataclass
class PlayerProfile:
    player_id: str
    wallet_ref: str
    total_score: int
    total_matches: int
    total_wins: int
    chassis_stats: ChassisStats
    last_seen_at: float


@dataclass
class LeaderboardEntry:
    rank: int
    player_id: str
    wallet_ref: str
    total_score: int
    wins: int
    matches: int


# -----------------------------------------------------------------------------
# In-memory state (simulates chain / DB)
# -----------------------------------------------------------------------------
class ArenaState:
    def __init__(self) -> None:
        self.arenas: Dict[int, ArenaRecord] = {}
        self.arena_phase: Dict[int, int] = {}
        self.arena_cooldown_until: Dict[int, int] = {}
        self.arena_bounty_pool: Dict[int, int] = {}
        self.platoon_slots: Dict[Tuple[int, int], PlatoonSlot] = {}
        self.unit_to_platoon_slot: Dict[str, int] = {}
        self.chassis_stats: Dict[str, ChassisStats] = {}
        self.matches: Dict[str, MatchRecord] = {}
        self.players: Dict[str, PlayerProfile] = {}
        self.arena_counter: int = 0
        self.global_tick: int = 0
        self.total_bounties_paid: int = 0
        self.paused: bool = False
        self.match_counter: int = 0


# -----------------------------------------------------------------------------
# Core engine
# -----------------------------------------------------------------------------
class RoborunRobotankArenaEngine:
    """Web3 game platform engine: arenas, matches, tanks, scoring."""

    def __init__(self) -> None:
        self.state = ArenaState()
        self._operator = OPERATOR_CORTEX_ADDRESS
        self._vault = PLATFORM_VAULT_ADDRESS
        self._treasury = ARENA_TREASURY_ADDRESS
        self._reward_pool = REWARD_POOL_ADDRESS
        self._oracle = ORACLE_NODE_ADDRESS

    def _require_operator(self, caller: str) -> None:
        if caller != self._operator:
            raise ArenaEngineNotOperator()

    def _next_arena_id(self) -> int:
        self.state.arena_counter += 1
        return self.state.arena_counter

    def _next_match_id(self) -> str:
        self.state.match_counter += 1
        raw = f"{PLATFORM_VERSION_HASH}{self.state.match_counter}{time.time()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def _platoon_key(self, arena_id: int, slot: int) -> Tuple[int, int]:
        return (arena_id, slot)

    def launch_arena(self, caller: str) -> int:
        self._require_operator(caller)
        if self.state.paused:
            raise ArenaEngineArenaPaused()
        arena_id = self._next_arena_id()
        self.state.global_tick += 1
        tick = self.state.global_tick
        self.state.arenas[arena_id] = ArenaRecord(
            arena_id=arena_id,
            start_tick=tick,
            phase=int(ArenaPhase.IDLE),
            terminated=False,
            bounty_claimed=0,
            created_at=time.time(),
        )
        self.state.arena_phase[arena_id] = int(ArenaPhase.IDLE)
        self.state.arena_cooldown_until[arena_id] = tick + ARENA_COOLDOWN_TICKS
        self.state.arena_bounty_pool[arena_id] = 0
        return arena_id

    def get_arena(self, arena_id: int) -> Optional[Dict[str, Any]]:
        if arena_id not in self.state.arenas:
            return None
        ar = self.state.arenas[arena_id]
        return {
            "arena_id": ar.arena_id,
            "start_tick": ar.start_tick,
            "phase": ar.phase,
            "terminated": ar.terminated,
            "bounty_claimed": ar.bounty_claimed,
            "created_at": ar.created_at,
        }

    def advance_arena_phase(self, arena_id: int, caller: str) -> int:
        self._require_operator(caller)
        if arena_id not in self.state.arenas:
            raise ArenaEngineArenaNotFound()
        ar = self.state.arenas[arena_id]
        if ar.terminated:
            raise ArenaEngineArenaPaused()
        if ar.phase >= MAX_PHASE_INDEX:
            raise ArenaEnginePhaseLocked()
        from_phase = ar.phase
        ar.phase = from_phase + 1
        self.state.arena_phase[arena_id] = ar.phase
        return ar.phase

    def assign_platoon_slot(
        self, arena_id: int, player_id: str, slot: int, caller: str
    ) -> None:
        self._require_operator(caller)
        if arena_id not in self.state.arenas:
            raise ArenaEngineArenaNotFound()
        if not player_id:
            raise ArenaEngineZeroDisallowed()
        if slot >= MAX_PLATOON_SIZE:
            raise ArenaEnginePlatoonFull()
        ar = self.state.arenas[arena_id]
        if ar.terminated:
            raise ArenaEnginePhaseLocked()
        key = self._platoon_key(arena_id, slot)
        if key in self.state.platoon_slots and self.state.platoon_slots[key].active:
            raise ArenaEnginePlatoonFull()
        self.state.global_tick += 1
        tick = self.state.global_tick
        self.state.platoon_slots[key] = PlatoonSlot(
            player_id=player_id,
            enlisted_at_tick=tick,
            active=True,
            battery_level=DEFAULT_STARTING_BATTERY,
            last_fire_tick=0,
        )
        self.state.unit_to_platoon_slot[player_id] = slot
        if player_id not in self.state.chassis_stats:
            self.state.chassis_stats[player_id] = ChassisStats()

    def fire_turret(
        self, arena_id: int, player_id: str, damage: int, current_tick: int
    ) -> None:
        if arena_id not in self.state.arenas:
            raise ArenaEngineArenaNotFound()
        if not player_id:
            raise ArenaEngineZeroDisallowed()
        slot = self.state.unit_to_platoon_slot.get(player_id, -1)
        if slot < 0:
            raise ArenaEngineChassisNotFound()
        key = self._platoon_key(arena_id, slot)
        if key not in self.state.platoon_slots:
            raise ArenaEngineChassisNotFound()
        pm = self.state.platoon_slots[key]
        if pm.player_id != player_id:
            raise ArenaEngineChassisNotFound()
        if pm.battery_level < MIN_BATTERY_TO_FIRE:
            raise ArenaEngineBatteryDepleted()
        if pm.last_fire_tick != 0 and current_tick < pm.last_fire_tick + TICK_MODULUS:
            raise ArenaEngineCooldownActive()
        pm.battery_level = max(0, pm.battery_level - BATTERY_DRAIN_PER_TICK * 2)
        pm.last_fire_tick = current_tick
        if player_id not in self.state.chassis_stats:
            self.state.chassis_stats[player_id] = ChassisStats()
        cs = self.state.chassis_stats[player_id]
        cs.damage_dealt += damage if damage > 0 else DAMAGE_PER_TURRET_FIRE
        cs.last_fire_tick = current_tick

    def charge_battery(self, player_id: str, amount: int, caller: str) -> None:
        self._require_operator(caller)
        if not player_id:
            raise ArenaEngineZeroDisallowed()
        if player_id not in self.state.chassis_stats and player_id not in self.state.unit_to_platoon_slot:
            raise ArenaEngineChassisNotFound()
        if player_id not in self.state.chassis_stats:
            self.state.chassis_stats[player_id] = ChassisStats()
        # Event-only in this engine; actual battery is in platoon slot per-arena
        pass

    def seed_bounty_pool(self, arena_id: int, amount: int, caller: str) -> None:
        self._require_operator(caller)
        if arena_id not in self.state.arenas:
            raise ArenaEngineArenaNotFound()
        if amount <= 0:
            raise ArenaEngineInvalidAmount()
        self.state.arena_bounty_pool[arena_id] = (
            self.state.arena_bounty_pool.get(arena_id, 0) + amount
        )

    def claim_bounty(self, arena_id: int, caller: str) -> int:
        self._require_operator(caller)
        if arena_id not in self.state.arenas:
            raise ArenaEngineArenaNotFound()
        ar = self.state.arenas[arena_id]
        if ar.terminated:
            raise ArenaEngineArenaPaused()
        if self.state.global_tick < self.state.arena_cooldown_until.get(arena_id, 0):
            raise ArenaEngineCooldownActive()
        pool = self.state.arena_bounty_pool.get(arena_id, 0)
        if pool <= 0:
            raise ArenaEngineInvalidAmount()
        self.state.arena_bounty_pool[arena_id] = 0
        ar.bounty_claimed += pool
        self.state.total_bounties_paid += pool
        self.state.arena_cooldown_until[arena_id] = (
            self.state.global_tick + ARENA_COOLDOWN_TICKS
        )
        return pool

    def terminate_arena(self, arena_id: int, caller: str) -> None:
        self._require_operator(caller)
        if arena_id not in self.state.arenas:
            raise ArenaEngineArenaNotFound()
        self.state.arenas[arena_id].terminated = True

    def flip_pause(self, caller: str) -> bool:
        self._require_operator(caller)
        self.state.paused = not self.state.paused
        return self.state.paused

    def get_platoon_slot(
        self, arena_id: int, slot: int
    ) -> Optional[Dict[str, Any]]:
        if arena_id not in self.state.arenas:
            return None
        key = self._platoon_key(arena_id, slot)
        if key not in self.state.platoon_slots:
            return None
        pm = self.state.platoon_slots[key]
        return {
            "player_id": pm.player_id,
            "enlisted_at_tick": pm.enlisted_at_tick,
            "active": pm.active,
            "battery_level": pm.battery_level,
            "last_fire_tick": pm.last_fire_tick,
        }

    def get_chassis_stats(self, player_id: str) -> Optional[Dict[str, Any]]:
        if player_id not in self.state.chassis_stats:
            return None
        cs = self.state.chassis_stats[player_id]
        return {
            "damage_dealt": cs.damage_dealt,
            "battles_won": cs.battles_won,
            "last_fire_tick": cs.last_fire_tick,
            "checkpoints_hit": cs.checkpoints_hit,
        }

    def get_arena_bounty_pool(self, arena_id: int) -> int:
        return self.state.arena_bounty_pool.get(arena_id, 0)

    def get_cooldown_until(self, arena_id: int) -> int:
        return self.state.arena_cooldown_until.get(arena_id, 0)

    def arena_counter(self) -> int:
        return self.state.arena_counter

    def total_bounties_paid(self) -> int:
        return self.state.total_bounties_paid

    def is_paused(self) -> bool:
        return self.state.paused

    def global_tick(self) -> int:
        return self.state.global_tick

    def tick_forward(self) -> int:
        self.state.global_tick += 1
        return self.state.global_tick


# -----------------------------------------------------------------------------
# Matchmaking and matches
# -----------------------------------------------------------------------------
class MatchmakingEngine:
    def __init__(self, arena_engine: RoborunRobotankArenaEngine) -> None:
        self.engine = arena_engine
        self.state = arena_engine.state

    def create_match(self, arena_id: int, participant_ids: List[str]) -> str:
        if arena_id not in self.state.arenas:
            raise ArenaEngineArenaNotFound()
        if len(participant_ids) > MAX_PLATOON_SIZE:
            raise ArenaEnginePlatoonFull()
        match_id = self.engine._next_match_id()
        tick = self.engine.global_tick()
        self.state.matches[match_id] = MatchRecord(
            match_id=match_id,
            arena_id=arena_id,
            status=int(MatchStatus.ACTIVE),
            start_tick=tick,
            end_tick=0,
            winner_player_id=None,
            participants=list(participant_ids),
            scores={p: 0 for p in participant_ids},
        )
        return match_id

    def get_match(self, match_id: str) -> Optional[Dict[str, Any]]:
        if match_id not in self.state.matches:
            return None
        m = self.state.matches[match_id]
        return {
            "match_id": m.match_id,
            "arena_id": m.arena_id,
            "status": m.status,
            "start_tick": m.start_tick,
            "end_tick": m.end_tick,
            "winner_player_id": m.winner_player_id,
            "participants": m.participants,
            "scores": dict(m.scores),
        }

    def add_match_score(self, match_id: str, player_id: str, points: int) -> None:
        if match_id not in self.state.matches:
            raise ArenaEngineMatchNotFound()
        m = self.state.matches[match_id]
        if m.status != int(MatchStatus.ACTIVE):
            raise ArenaEngineMatchNotActive()
        if player_id not in m.scores:
            m.scores[player_id] = 0
        m.scores[player_id] += points

    def finish_match(self, match_id: str, winner_player_id: Optional[str]) -> None:
        if match_id not in self.state.matches:
            raise ArenaEngineMatchNotFound()
        m = self.state.matches[match_id]
        if m.status != int(MatchStatus.ACTIVE):
            raise ArenaEngineMatchNotActive()
        m.status = int(MatchStatus.FINISHED)
        m.end_tick = self.engine.global_tick()
        m.winner_player_id = winner_player_id
        for pid in m.participants:
            if pid in self.state.chassis_stats:
                self.state.chassis_stats[pid].battles_won += (
                    1 if pid == winner_player_id else 0
                )
            if pid not in self.state.players:
                continue
            prof = self.state.players[pid]
            prof.total_matches += 1
            if pid == winner_player_id:
                prof.total_wins += 1
            prof.total_score += m.scores.get(pid, 0)
            prof.last_seen_at = time.time()


# -----------------------------------------------------------------------------
# Player and leaderboard
# -----------------------------------------------------------------------------
class PlayerRegistry:
    def __init__(self, arena_engine: RoborunRobotankArenaEngine) -> None:
        self.engine = arena_engine
        self.state = arena_engine.state

    def get_or_create_player(self, player_id: str, wallet_ref: str) -> PlayerProfile:
        if not player_id or not wallet_ref:
            raise ArenaEngineZeroDisallowed()
        if player_id in self.state.players:
            p = self.state.players[player_id]
            p.last_seen_at = time.time()
            return p
        stats = self.state.chassis_stats.get(
            player_id, ChassisStats()
        )
        prof = PlayerProfile(
            player_id=player_id,
            wallet_ref=wallet_ref,
            total_score=0,
            total_matches=0,
            total_wins=0,
            chassis_stats=stats,
            last_seen_at=time.time(),
        )
        self.state.players[player_id] = prof
        if player_id not in self.state.chassis_stats:
            self.state.chassis_stats[player_id] = stats
        return prof

    def get_player(self, player_id: str) -> Optional[PlayerProfile]:
        return self.state.players.get(player_id)

    def get_leaderboard(self, top_n: int = LEADERBOARD_TOP_N) -> List[LeaderboardEntry]:
        candidates = [
            (p.total_score, p.player_id, p.wallet_ref, p.total_wins, p.total_matches)
            for p in self.state.players.values()
        ]
        candidates.sort(key=lambda x: (-x[0], -x[3], -x[4]))
        result = []
        for rank, (score, pid, wallet, wins, matches) in enumerate(
            candidates[:top_n], start=1
        ):
            result.append(
                LeaderboardEntry(
                    rank=rank,
                    player_id=pid,
                    wallet_ref=wallet,
                    total_score=score,
                    wins=wins,
                    matches=matches,
                )
            )
        return result


# -----------------------------------------------------------------------------
# Validation and hex helpers (unique, no reuse from other contracts)
# -----------------------------------------------------------------------------
def _validate_eth_like_address(addr: str) -> bool:
    if not addr or not isinstance(addr, str):
        return False
    addr = addr.strip()
    if len(addr) != 42 or not addr.startswith("0x"):
        return False
    try:
        int(addr[2:], 16)
        return True
    except ValueError:
        return False


def _validate_hex_salt(hex_str: str, min_len: int = 32) -> bool:
    if not hex_str or not isinstance(hex_str, str):
        return False
    hex_str = hex_str.strip()
    if not hex_str.startswith("0x") or len(hex_str) < min_len:
        return False
    try:
        int(hex_str[2:], 16)
        return True
    except ValueError:
        return False


def _compute_cue_id(payload: str, nonce: int) -> str:
    raw = f"{CHASSIS_MINT_SALT}{payload}{nonce}{MATCHMAKING_SEED}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _compute_arena_domain(arena_id: int) -> str:
    raw = f"{ARENA_DOMAIN_SALT}{arena_id}{PLATFORM_VERSION_HASH}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _validate_arena_id(arena_id: int) -> bool:
    return isinstance(arena_id, int) and 1 <= arena_id <= MAX_ACTIVE_ARENAS * 2


def _validate_slot(slot: int) -> bool:
    return isinstance(slot, int) and 0 <= slot < MAX_PLATOON_SIZE


def _validate_player_id(player_id: str) -> bool:
    return (
        isinstance(player_id, str)
        and len(player_id) >= 1
        and len(player_id) <= 256
    )


def _validate_amount(amount: int) -> bool:
    return isinstance(amount, int) and amount >= 0


# -----------------------------------------------------------------------------
# Event log (simulated on-chain events for web3 platform)
# -----------------------------------------------------------------------------
@dataclass
class PlatformEvent:
    event_type: str
    payload: Dict[str, Any]
    tick: int
    timestamp: float
    event_id: str


class EventLog:
    def __init__(self, max_events: int = 10000) -> None:
        self._events: List[PlatformEvent] = []
        self._max_events = max_events

    def emit(self, event_type: str, payload: Dict[str, Any], tick: int) -> str:
        eid = str(uuid.uuid4())
        self._events.append(
            PlatformEvent(
                event_type=event_type,
                payload={**payload, "event_id": eid},
                tick=tick,
                timestamp=time.time(),
                event_id=eid,
            )
        )
        while len(self._events) > self._max_events:
            self._events.pop(0)
        return eid

    def get_recent(self, limit: int = 100) -> List[Dict[str, Any]]:
        out = []
        for e in self._events[-limit:]:
            out.append(
                {
                    "event_type": e.event_type,
                    "payload": e.payload,
                    "tick": e.tick,
                    "timestamp": e.timestamp,
                    "event_id": e.event_id,
                }
            )
        return list(reversed(out))

    def get_by_type(self, event_type: str, limit: int = 50) -> List[Dict[str, Any]]:
        out = [e for e in self._events if e.event_type == event_type][-limit:]
        return [
            {
                "event_type": e.event_type,
                "payload": e.payload,
                "tick": e.tick,
                "timestamp": e.timestamp,
                "event_id": e.event_id,
            }
            for e in reversed(out)
        ]


# -----------------------------------------------------------------------------
# Session manager (player sessions for web3 game)
# -----------------------------------------------------------------------------
@dataclass
class GameSession:
    session_id: str
    player_id: str
    arena_id: int
    match_id: Optional[str]
    created_at: float
    last_activity_at: float


class SessionManager:
    def __init__(self, timeout_seconds: int = SESSION_TIMEOUT_SECONDS) -> None:
        self._sessions: Dict[str, GameSession] = {}
        self._player_to_sessions: Dict[str, List[str]] = {}
        self._timeout = timeout_seconds

    def create_session(
        self, player_id: str, arena_id: int, match_id: Optional[str] = None
    ) -> str:
        sid = str(uuid.uuid4())
        now = time.time()
        self._sessions[sid] = GameSession(
            session_id=sid,
            player_id=player_id,
            arena_id=arena_id,
            match_id=match_id,
            created_at=now,
            last_activity_at=now,
        )
        if player_id not in self._player_to_sessions:
            self._player_to_sessions[player_id] = []
        self._player_to_sessions[player_id].append(sid)
        return sid

    def touch_session(self, session_id: str) -> bool:
        if session_id not in self._sessions:
            return False
        self._sessions[session_id].last_activity_at = time.time()
        return True

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        if session_id not in self._sessions:
            return None
        s = self._sessions[session_id]
        if time.time() - s.last_activity_at > self._timeout:
            self.end_session(session_id)
            return None
        return {
            "session_id": s.session_id,
            "player_id": s.player_id,
            "arena_id": s.arena_id,
            "match_id": s.match_id,
            "created_at": s.created_at,
            "last_activity_at": s.last_activity_at,
        }

    def end_session(self, session_id: str) -> None:
        if session_id in self._sessions:
            pid = self._sessions[session_id].player_id
            del self._sessions[session_id]
            if pid in self._player_to_sessions:
                self._player_to_sessions[pid] = [
                    x for x in self._player_to_sessions[pid] if x != session_id
                ]
                if not self._player_to_sessions[pid]:
                    del self._player_to_sessions[pid]

    def cleanup_stale(self) -> int:
        now = time.time()
        to_remove = [
            sid for sid, s in self._sessions.items()
            if now - s.last_activity_at > self._timeout
        ]
        for sid in to_remove:
            self.end_session(sid)
        return len(to_remove)


# -----------------------------------------------------------------------------
# Checkpoint and battery logic (runner game integration)
# -----------------------------------------------------------------------------
class CheckpointEngine:
    def __init__(self, arena_engine: RoborunRobotankArenaEngine) -> None:
        self.engine = arena_engine
        self.state = arena_engine.state
        self._checkpoint_distances: Dict[Tuple[int, str], int] = {}

    def record_checkpoint(
        self, arena_id: int, player_id: str, distance: int, current_tick: int
    ) -> bool:
        if arena_id not in self.state.arenas:
            return False
        key = (arena_id, player_id)
        last = self._checkpoint_distances.get(key, 0)
        if distance < last or distance - last < 100:
            return False
        self._checkpoint_distances[key] = distance
        if player_id in self.state.chassis_stats:
            self.state.chassis_stats[player_id].checkpoints_hit += 1
        slot = self.state.unit_to_platoon_slot.get(player_id, -1)
        if slot >= 0:
            pk = self.engine._platoon_key(arena_id, slot)
            if pk in self.state.platoon_slots:
                pm = self.state.platoon_slots[pk]
                pm.battery_level = min(
                    DEFAULT_STARTING_BATTERY,
                    pm.battery_level + BATTERY_RECHARGE_AT_CHECKPOINT,
                )
        return True

    def get_last_checkpoint_distance(self, arena_id: int, player_id: str) -> int:
        return self._checkpoint_distances.get((arena_id, player_id), 0)


# -----------------------------------------------------------------------------
# Unified platform API (single entry for web)
# -----------------------------------------------------------------------------
class RoborunRobotankPlatform:
    """Single entry point: arena engine + matchmaking + players + leaderboard."""

    def __init__(self) -> None:
        self._engine = RoborunRobotankArenaEngine()
        self._matchmaking = MatchmakingEngine(self._engine)
        self._players = PlayerRegistry(self._engine)
        self._event_log = EventLog()
        self._sessions = SessionManager()
        self._checkpoints = CheckpointEngine(self._engine)
        self._operator = OPERATOR_CORTEX_ADDRESS

    @property
    def engine(self) -> RoborunRobotankArenaEngine:
        return self._engine

    @property
    def matchmaking(self) -> MatchmakingEngine:
        return self._matchmaking

    @property
    def players(self) -> PlayerRegistry:
        return self._players

    def config_snapshot(self) -> Dict[str, Any]:
        return {
            "arena_treasury": ARENA_TREASURY_ADDRESS,
            "platform_vault": PLATFORM_VAULT_ADDRESS,
            "reward_pool": REWARD_POOL_ADDRESS,
            "operator_cortex": OPERATOR_CORTEX_ADDRESS,
            "oracle_node": ORACLE_NODE_ADDRESS,
            "arena_domain_salt": ARENA_DOMAIN_SALT,
            "platform_version_hash": PLATFORM_VERSION_HASH,
            "max_platoon_size": MAX_PLATOON_SIZE,
            "arena_cooldown_ticks": ARENA_COOLDOWN_TICKS,
            "phase_duration_blocks": PHASE_DURATION_BLOCKS,
            "max_phase_index": MAX_PHASE_INDEX,
            "bounty_base_units": BOUNTY_BASE_UNITS,
            "tick_modulus": TICK_MODULUS,
            "vault_share_bps": VAULT_SHARE_BPS,
            "control_share_bps": CONTROL_SHARE_BPS,
        }

    def api_launch_arena(self, caller: str) -> Dict[str, Any]:
        aid = self._engine.launch_arena(caller)
        return {"arena_id": aid, "global_tick": self._engine.global_tick()}

    def api_get_arena(self, arena_id: int) -> Dict[str, Any]:
        out = self._engine.get_arena(arena_id)
        if out is None:
            return {"error": "ArenaEngineArenaNotFound"}
        return out

    def api_advance_phase(self, arena_id: int, caller: str) -> Dict[str, Any]:
        phase = self._engine.advance_arena_phase(arena_id, caller)
        return {"arena_id": arena_id, "phase": phase}

    def api_assign_slot(
        self, arena_id: int, player_id: str, slot: int, caller: str
    ) -> Dict[str, Any]:
        self._engine.assign_platoon_slot(arena_id, player_id, slot, caller)
        return {"arena_id": arena_id, "player_id": player_id, "slot": slot}

    def api_fire_turret(
        self, arena_id: int, player_id: str, damage: int, caller: str
    ) -> Dict[str, Any]:
        tick = self._engine.global_tick()
        self._engine.fire_turret(arena_id, player_id, damage, tick)
        return {"arena_id": arena_id, "player_id": player_id, "tick": tick}

    def api_seed_bounty(self, arena_id: int, amount: int, caller: str) -> Dict[str, Any]:
        self._engine.seed_bounty_pool(arena_id, amount, caller)
        return {"arena_id": arena_id, "new_pool": self._engine.get_arena_bounty_pool(arena_id)}

    def api_claim_bounty(self, arena_id: int, caller: str) -> Dict[str, Any]:
        paid = self._engine.claim_bounty(arena_id, caller)
        return {"arena_id": arena_id, "amount": paid}

    def api_terminate_arena(self, arena_id: int, caller: str) -> Dict[str, Any]:
        self._engine.terminate_arena(arena_id, caller)
        return {"arena_id": arena_id}

    def api_flip_pause(self, caller: str) -> Dict[str, Any]:
        paused = self._engine.flip_pause(caller)
        return {"paused": paused}

    def api_get_platoon_slot(self, arena_id: int, slot: int) -> Dict[str, Any]:
        out = self._engine.get_platoon_slot(arena_id, slot)
        if out is None:
            return {"error": "slot_empty_or_invalid"}
        return out

    def api_get_chassis_stats(self, player_id: str) -> Dict[str, Any]:
        out = self._engine.get_chassis_stats(player_id)
        if out is None:
            return {"error": "ChassisNotFound"}
        return out

    def api_create_match(
        self, arena_id: int, participant_ids: List[str], caller: str
    ) -> Dict[str, Any]:
        self._engine._require_operator(caller)
        match_id = self._matchmaking.create_match(arena_id, participant_ids)
        return {"match_id": match_id, "arena_id": arena_id}

    def api_get_match(self, match_id: str) -> Dict[str, Any]:
        out = self._matchmaking.get_match(match_id)
        if out is None:
            return {"error": "MatchNotFound"}
        return out

    def api_add_match_score(
        self, match_id: str, player_id: str, points: int
    ) -> Dict[str, Any]:
        self._matchmaking.add_match_score(match_id, player_id, points)
        return {"match_id": match_id, "player_id": player_id}

    def api_finish_match(
        self, match_id: str, winner_player_id: Optional[str]
    ) -> Dict[str, Any]:
        self._matchmaking.finish_match(match_id, winner_player_id)
        return {"match_id": match_id, "winner": winner_player_id}

    def api_get_or_create_player(self, player_id: str, wallet_ref: str) -> Dict[str, Any]:
        prof = self._players.get_or_create_player(player_id, wallet_ref)
        return {
            "player_id": prof.player_id,
            "wallet_ref": prof.wallet_ref,
            "total_score": prof.total_score,
            "total_matches": prof.total_matches,
            "total_wins": prof.total_wins,
        }

    def api_get_player(self, player_id: str) -> Dict[str, Any]:
        prof = self._players.get_player(player_id)
        if prof is None:
            return {"error": "PlayerNotFound"}
        return {
            "player_id": prof.player_id,
            "wallet_ref": prof.wallet_ref,
            "total_score": prof.total_score,
            "total_matches": prof.total_matches,
            "total_wins": prof.total_wins,
            "last_seen_at": prof.last_seen_at,
        }

    def api_get_leaderboard(self, top_n: int = LEADERBOARD_TOP_N) -> Dict[str, Any]:
        entries = self._players.get_leaderboard(top_n)
        return {
            "entries": [
                {
                    "rank": e.rank,
                    "player_id": e.player_id,
                    "wallet_ref": e.wallet_ref,
                    "total_score": e.total_score,
                    "wins": e.wins,
                    "matches": e.matches,
                }
                for e in entries
            ]
        }

    def api_tick(self) -> Dict[str, Any]:
        tick = self._engine.tick_forward()
        return {"global_tick": tick}

    def api_record_checkpoint(
        self, arena_id: int, player_id: str, distance: int
    ) -> Dict[str, Any]:
        tick = self._engine.global_tick()
        ok = self._checkpoints.record_checkpoint(arena_id, player_id, distance, tick)
        return {"recorded": ok, "arena_id": arena_id, "player_id": player_id}

    def api_get_recent_events(self, limit: int = 100) -> Dict[str, Any]:
        return {"events": self._event_log.get_recent(limit)}

    def api_get_events_by_type(
        self, event_type: str, limit: int = 50
    ) -> Dict[str, Any]:
        return {"events": self._event_log.get_by_type(event_type, limit)}

    def api_create_session(
        self, player_id: str, arena_id: int, match_id: Optional[str] = None
    ) -> Dict[str, Any]:
        sid = self._sessions.create_session(player_id, arena_id, match_id)
        return {"session_id": sid, "player_id": player_id, "arena_id": arena_id}

    def api_touch_session(self, session_id: str) -> Dict[str, Any]:
        ok = self._sessions.touch_session(session_id)
        return {"ok": ok, "session_id": session_id}

    def api_get_session(self, session_id: str) -> Dict[str, Any]:
        out = self._sessions.get_session(session_id)
        if out is None:
            return {"error": "SessionNotFoundOrExpired"}
        return out

    def api_end_session(self, session_id: str) -> Dict[str, Any]:
        self._sessions.end_session(session_id)
        return {"session_id": session_id}

    def api_cleanup_stale_sessions(self) -> Dict[str, Any]:
        n = self._sessions.cleanup_stale()
        return {"removed": n}

    def api_validate_address(self, addr: str) -> Dict[str, Any]:
        return {"valid": _validate_eth_like_address(addr), "address": addr}

    def api_validate_hex_salt(self, hex_str: str) -> Dict[str, Any]:
        return {"valid": _validate_hex_salt(hex_str), "hex": hex_str[:64]}

    def api_compute_cue_id(self, payload: str, nonce: int) -> Dict[str, Any]:
        return {"cue_id": _compute_cue_id(payload, nonce)}

    def api_compute_arena_domain(self, arena_id: int) -> Dict[str, Any]:
        return {"domain_hash": _compute_arena_domain(arena_id)}

    def api_batch_get_arenas(self, arena_ids: List[int]) -> Dict[str, Any]:
        out = []
        for aid in arena_ids:
            a = self._engine.get_arena(aid)
            out.append(a if a is not None else {"arena_id": aid, "error": "NotFound"})
        return {"arenas": out}

    def api_batch_get_platoon_slots(
        self, arena_id: int, slots: List[int]
    ) -> Dict[str, Any]:
        out = []
        for slot in slots:
            s = self._engine.get_platoon_slot(arena_id, slot)
            out.append(
                s if s is not None else {"arena_id": arena_id, "slot": slot, "error": "Empty"}
            )
        return {"slots": out}

    def api_batch_get_chassis_stats(
        self, player_ids: List[str]
    ) -> Dict[str, Any]:
        out = []
        for pid in player_ids:
            c = self._engine.get_chassis_stats(pid)
            out.append(
                c if c is not None else {"player_id": pid, "error": "NotFound"}
            )
        return {"chassis_stats": out}

    def api_get_phase_label(self, phase: int) -> Dict[str, Any]:
        labels = [
            "Idle", "Warmup", "Engaged", "Peak", "Closure", "Settle", "Terminal"
        ]
        if 0 <= phase < len(labels):
            return {"phase": phase, "label": labels[phase]}
        return {"phase": phase, "label": "Unknown"}

    def api_can_claim_bounty(self, arena_id: int) -> Dict[str, Any]:
        if arena_id not in self._engine.state.arenas:
            return {"can_claim": False, "reason": "ArenaNotFound"}
        ar = self._engine.state.arenas[arena_id]
        if ar.terminated:
            return {"can_claim": False, "reason": "ArenaTerminated"}
        tick = self._engine.global_tick()
        if tick < self._engine.get_cooldown_until(arena_id):
            return {"can_claim": False, "reason": "CooldownActive"}
        pool = self._engine.get_arena_bounty_pool(arena_id)
        if pool <= 0:
            return {"can_claim": False, "reason": "PoolEmpty"}
        return {"can_claim": True, "pool": pool}


# -----------------------------------------------------------------------------
# Serialization for HTTP / JSON
# -----------------------------------------------------------------------------
def platform_to_json(platform: RoborunRobotankPlatform) -> str:
    """Export minimal snapshot for persistence or debugging."""
    state = platform._engine.state
    data = {
        "arena_counter": state.arena_counter,
        "global_tick": state.global_tick,
        "total_bounties_paid": state.total_bounties_paid,
        "paused": state.paused,
        "config": platform.config_snapshot(),
    }
    return json.dumps(data, indent=2)


def create_platform() -> RoborunRobotankPlatform:
    """Factory: one platform instance with all config pre-populated."""
    return RoborunRobotankPlatform()


def run_simulation(
    platform: RoborunRobotankPlatform,
    num_arenas: int = 3,
    players_per_arena: int = 4,
    ticks_per_arena: int = 50,
) -> Dict[str, Any]:
    """
    Run a full simulation: launch arenas, assign players, create matches,
    fire turrets, record checkpoints, seed and claim bounties, advance phases.
    Returns summary stats.
    """
    operator = OPERATOR_CORTEX_ADDRESS
    results = {"arenas_launched": 0, "matches_created": 0, "errors": []}
    arena_ids = []
    for i in range(num_arenas):
        try:
            r = platform.api_launch_arena(operator)
            arena_ids.append(r["arena_id"])
            results["arenas_launched"] += 1
        except Exception as e:
            results["errors"].append({"stage": "launch_arena", "error": str(e)})
    player_ids = [f"sim_player_{j}" for j in range(players_per_arena * num_arenas)]
    for idx, aid in enumerate(arena_ids):
        for slot, j in enumerate(range(players_per_arena)):
            pid = player_ids[idx * players_per_arena + j]
            try:
                platform.api_get_or_create_player(pid, ARENA_TREASURY_ADDRESS)
                platform.api_assign_slot(aid, pid, slot, operator)
            except Exception as e:
                results["errors"].append({"stage": "assign_slot", "error": str(e)})
        try:
            participants = [
                player_ids[idx * players_per_arena + k]
                for k in range(players_per_arena)
            ]
            r = platform.api_create_match(aid, participants, operator)
            results["matches_created"] += 1
        except Exception as e:
            results["errors"].append({"stage": "create_match", "error": str(e)})
    for _ in range(ticks_per_arena):
        platform.api_tick()
    for aid in arena_ids:
        for slot in range(players_per_arena):
            pid = player_ids[arena_ids.index(aid) * players_per_arena + slot]
            try:
                platform.api_fire_turret(aid, pid, DAMAGE_PER_TURRET_FIRE, operator)
            except Exception:
                pass
        try:
            platform.api_seed_bounty(aid, 500_000, operator)
        except Exception:
            pass
    for aid in arena_ids:
        for _ in range(ARENA_COOLDOWN_TICKS + 5):
            platform.api_tick()
        try:
            platform.api_claim_bounty(aid, operator)
        except Exception:
            pass
    results["global_tick"] = platform._engine.global_tick()
    results["total_bounties_paid"] = platform._engine.total_bounties_paid()
    results["leaderboard_count"] = len(
        platform.api_get_leaderboard(LEADERBOARD_TOP_N).get("entries", [])
    )
    return results


def run_demo(platform: RoborunRobotankPlatform) -> None:
    """Run a short demo: one arena, two players, one match, fire and finish."""
    operator = OPERATOR_CORTEX_ADDRESS
    platform.api_launch_arena(operator)
    aid = platform._engine.arena_counter()
    platform.api_get_or_create_player("demo_p1", PLATFORM_VAULT_ADDRESS)
    platform.api_get_or_create_player("demo_p2", PLATFORM_VAULT_ADDRESS)
    platform.api_assign_slot(aid, "demo_p1", 0, operator)
    platform.api_assign_slot(aid, "demo_p2", 1, operator)
    platform.api_create_match(aid, ["demo_p1", "demo_p2"], operator)
    for _ in range(10):
        platform.api_tick()
    platform.api_fire_turret(aid, "demo_p1", 15, operator)
    platform.api_fire_turret(aid, "demo_p2", 15, operator)
    match_id = list(platform._engine.state.matches.keys())[-1]
    platform.api_add_match_score(match_id, "demo_p1", SCORE_PER_CHECKPOINT)
    platform.api_add_match_score(match_id, "demo_p2", SCORE_PER_KILL)
    platform.api_finish_match(match_id, "demo_p1")
    print("Demo finished. Leaderboard:", platform.api_get_leaderboard(10))


def get_all_constants() -> Dict[str, Any]:
    """Return all platform constants for documentation or UI."""
    return {
        "ARENA_TREASURY_ADDRESS": ARENA_TREASURY_ADDRESS,
        "PLATFORM_VAULT_ADDRESS": PLATFORM_VAULT_ADDRESS,
        "REWARD_POOL_ADDRESS": REWARD_POOL_ADDRESS,
        "OPERATOR_CORTEX_ADDRESS": OPERATOR_CORTEX_ADDRESS,
        "ORACLE_NODE_ADDRESS": ORACLE_NODE_ADDRESS,
        "ARENA_DOMAIN_SALT": ARENA_DOMAIN_SALT,
        "PLATFORM_VERSION_HASH": PLATFORM_VERSION_HASH,
        "CHASSIS_MINT_SALT": CHASSIS_MINT_SALT,
        "MATCHMAKING_SEED": MATCHMAKING_SEED,
        "MAX_PLATOON_SIZE": MAX_PLATOON_SIZE,
        "ARENA_COOLDOWN_TICKS": ARENA_COOLDOWN_TICKS,
        "PHASE_DURATION_BLOCKS": PHASE_DURATION_BLOCKS,
        "MAX_PHASE_INDEX": MAX_PHASE_INDEX,
        "BOUNTY_BASE_UNITS": BOUNTY_BASE_UNITS,
        "TICK_MODULUS": TICK_MODULUS,
        "VAULT_SHARE_BPS": VAULT_SHARE_BPS,
        "CONTROL_SHARE_BPS": CONTROL_SHARE_BPS,
        "MAX_ACTIVE_ARENAS": MAX_ACTIVE_ARENAS,
        "MAX_MATCHES_PER_ARENA": MAX_MATCHES_PER_ARENA,
        "BATTERY_DRAIN_PER_TICK": BATTERY_DRAIN_PER_TICK,
        "BATTERY_RECHARGE_AT_CHECKPOINT": BATTERY_RECHARGE_AT_CHECKPOINT,
        "DEFAULT_STARTING_BATTERY": DEFAULT_STARTING_BATTERY,
        "MIN_BATTERY_TO_FIRE": MIN_BATTERY_TO_FIRE,
        "DAMAGE_PER_TURRET_FIRE": DAMAGE_PER_TURRET_FIRE,
        "SCORE_PER_CHECKPOINT": SCORE_PER_CHECKPOINT,
        "SCORE_PER_KILL": SCORE_PER_KILL,
        "LEADERBOARD_TOP_N": LEADERBOARD_TOP_N,
        "SESSION_TIMEOUT_SECONDS": SESSION_TIMEOUT_SECONDS,
    }


def validate_platform_config() -> List[str]:
    """Validate that all addresses and hex constants are well-formed. Returns list of errors."""
    errors = []
    for name, val in [
        ("ARENA_TREASURY_ADDRESS", ARENA_TREASURY_ADDRESS),
        ("PLATFORM_VAULT_ADDRESS", PLATFORM_VAULT_ADDRESS),
        ("REWARD_POOL_ADDRESS", REWARD_POOL_ADDRESS),
        ("OPERATOR_CORTEX_ADDRESS", OPERATOR_CORTEX_ADDRESS),
        ("ORACLE_NODE_ADDRESS", ORACLE_NODE_ADDRESS),
    ]:
        if not _validate_eth_like_address(val):
            errors.append(f"{name} is not a valid address")
    for name, val in [
        ("ARENA_DOMAIN_SALT", ARENA_DOMAIN_SALT),
        ("PLATFORM_VERSION_HASH", PLATFORM_VERSION_HASH),
        ("CHASSIS_MINT_SALT", CHASSIS_MINT_SALT),
        ("MATCHMAKING_SEED", MATCHMAKING_SEED),
    ]:
        if not _validate_hex_salt(val, 16):
            errors.append(f"{name} is not a valid hex salt")
    if MAX_PLATOON_SIZE <= 0 or MAX_PLATOON_SIZE > 256:
        errors.append("MAX_PLATOON_SIZE out of range")
    if VAULT_SHARE_BPS + CONTROL_SHARE_BPS != 100:
        errors.append("VAULT_SHARE_BPS + CONTROL_SHARE_BPS must equal 100")
    return errors


def export_leaderboard_csv(platform: RoborunRobotankPlatform, top_n: int = 100) -> str:
    """Export leaderboard as CSV string."""
    data = platform.api_get_leaderboard(top_n)
    lines = ["rank,player_id,wallet_ref,total_score,wins,matches"]
    for e in data.get("entries", []):
        lines.append(
            f"{e['rank']},{e['player_id']},{e['wallet_ref']},{e['total_score']},{e['wins']},{e['matches']}"
        )
    return "\n".join(lines)


def import_players_bulk(
    platform: RoborunRobotankPlatform,
    entries: List[Tuple[str, str]],
) -> Dict[str, Any]:
    """Bulk register players. entries = [(player_id, wallet_ref), ...]."""
    created = 0
    errors = []
    for player_id, wallet_ref in entries:
        try:
            platform.api_get_or_create_player(player_id, wallet_ref)
            created += 1
        except Exception as e:
            errors.append({"player_id": player_id, "error": str(e)})
    return {"created": created, "errors": errors}


def compute_vault_split(amount: int) -> Tuple[int, int]:
    """Compute vault and control share from total amount (bps)."""
    vault_part = (amount * VAULT_SHARE_BPS) // 100
    control_part = amount - vault_part
    return (vault_part, control_part)


def phase_label(phase: int) -> str:
    """Human-readable phase label."""
    labels = [
        "Idle", "Warmup", "Engaged", "Peak", "Closure", "Settle", "Terminal"
    ]
    return labels[phase] if 0 <= phase < len(labels) else "Unknown"


# -----------------------------------------------------------------------------
# Summary types and aggregate API (for HuxleyGames / web UI)
# -----------------------------------------------------------------------------
@dataclass
class ArenaSummary:
    arena_id: int
    phase: int
    phase_label: str
    terminated: bool
    bounty_pool: int
    cooldown_until: int
    can_claim_bounty: bool


@dataclass
class MatchSummary:
    match_id: str
    arena_id: int
    status: int
    status_label: str
    participant_count: int
    winner_player_id: Optional[str]
    scores: Dict[str, int]


def get_arena_summary(platform: RoborunRobotankPlatform, arena_id: int) -> Optional[ArenaSummary]:
    a = platform._engine.get_arena(arena_id)
    if a is None:
        return None
    pool = platform._engine.get_arena_bounty_pool(arena_id)
    cooldown = platform._engine.get_cooldown_until(arena_id)
    tick = platform._engine.global_tick()
    can_claim = (
        not a["terminated"]
        and tick >= cooldown
        and pool > 0
    )
    return ArenaSummary(
        arena_id=arena_id,
        phase=a["phase"],
        phase_label=phase_label(a["phase"]),
        terminated=a["terminated"],
        bounty_pool=pool,
        cooldown_until=cooldown,
        can_claim_bounty=can_claim,
    )


def get_match_summary(platform: RoborunRobotankPlatform, match_id: str) -> Optional[MatchSummary]:
    m = platform._matchmaking.get_match(match_id)
    if m is None:
        return None
    status_labels = ["Pending", "Active", "Finished", "Cancelled"]
    st = m["status"]
    label = status_labels[st] if 0 <= st < len(status_labels) else "Unknown"
    return MatchSummary(
        match_id=m["match_id"],
        arena_id=m["arena_id"],
        status=m["status"],
        status_label=label,
        participant_count=len(m["participants"]),
        winner_player_id=m.get("winner_player_id"),
        scores=dict(m.get("scores", {})),
    )


def api_get_arena_summary(platform: RoborunRobotankPlatform, arena_id: int) -> Dict[str, Any]:
    s = get_arena_summary(platform, arena_id)
    if s is None:
        return {"error": "ArenaNotFound"}
    return asdict(s)


def api_get_match_summary(platform: RoborunRobotankPlatform, match_id: str) -> Dict[str, Any]:
    s = get_match_summary(platform, match_id)
    if s is None:
        return {"error": "MatchNotFound"}
    return asdict(s)


def run_simulation_v2(
    platform: RoborunRobotankPlatform,
    num_arenas: int = 5,
    players_per_arena: int = 6,
    ticks_per_phase: int = 30,
    advance_phases: bool = True,
) -> Dict[str, Any]:
    """
    Extended simulation: multiple arenas, phase advances, checkpoints, sessions,
    leaderboard and event log checks.
    """
    operator = OPERATOR_CORTEX_ADDRESS
    results = {
        "arenas": [],
        "matches": [],
        "sessions_created": 0,
        "checkpoints_recorded": 0,
        "final_leaderboard_len": 0,
        "errors": [],
    }
    for i in range(num_arenas):
        try:
            r = platform.api_launch_arena(operator)
            aid = r["arena_id"]
            results["arenas"].append(aid)
            if advance_phases:
                platform.api_advance_phase(aid, operator)
        except Exception as e:
            results["errors"].append({"launch_arena": str(e)})
    all_players = []
    for idx, aid in enumerate(results["arenas"]):
        for j in range(players_per_arena):
            pid = f"v2_player_{idx}_{j}"
            all_players.append((pid, aid))
            try:
                platform.api_get_or_create_player(pid, REWARD_POOL_ADDRESS)
                platform.api_assign_slot(aid, pid, j, operator)
                sid = platform.api_create_session(pid, aid)
                if sid:
                    results["sessions_created"] += 1
            except Exception as e:
                results["errors"].append({"assign": str(e)})
    for idx, aid in enumerate(results["arenas"]):
        participants = [p[0] for p in all_players if p[1] == aid]
        try:
            r = platform.api_create_match(aid, participants, operator)
            results["matches"].append(r["match_id"])
        except Exception as e:
            results["errors"].append({"create_match": str(e)})
    for step in range(ticks_per_phase * (MAX_PHASE_INDEX + 1)):
        platform.api_tick()
        for (pid, aid) in all_players[: 2 * players_per_arena]:
            try:
                platform.api_record_checkpoint(aid, pid, 100 + step * 50)
                results["checkpoints_recorded"] += 1
            except Exception:
                pass
        if step % TICK_MODULUS == 0 and step > 0:
            for (pid, aid) in all_players[: 4]:
                try:
                    platform.api_fire_turret(aid, pid, DAMAGE_PER_TURRET_FIRE, operator)
                except Exception:
                    pass
    for aid in results["arenas"]:
        try:
            platform.api_seed_bounty(aid, BOUNTY_BASE_UNITS, operator)
        except Exception:
            pass
    for _ in range(ARENA_COOLDOWN_TICKS + 10):
        platform.api_tick()
    for aid in results["arenas"]:
        try:
            platform.api_claim_bounty(aid, operator)
        except Exception:
            pass
    for match_id in results["matches"][:1]:
        try:
            platform.api_add_match_score(match_id, all_players[0][0], SCORE_PER_KILL * 3)
            platform.api_finish_match(match_id, all_players[0][0])
        except Exception:
            pass
    results["final_leaderboard_len"] = len(
        platform.api_get_leaderboard(LEADERBOARD_TOP_N).get("entries", [])
    )
    results["global_tick"] = platform._engine.global_tick()
    results["total_bounties_paid"] = platform._engine.total_bounties_paid()
    return results


def health_check(platform: RoborunRobotankPlatform) -> Dict[str, Any]:
    """Check platform health: config validation, constants, and state sanity."""
    config_errors = validate_platform_config()
    return {
        "ok": len(config_errors) == 0,
        "config_errors": config_errors,
        "arena_counter": platform._engine.arena_counter(),
        "global_tick": platform._engine.global_tick(),
        "paused": platform._engine.is_paused(),
    }


def readiness_check(platform: RoborunRobotankPlatform) -> Dict[str, Any]:
    """Readiness for web: addresses set, not paused, constants valid."""
    h = health_check(platform)
    ready = (
        h["ok"]
        and not h["paused"]
        and _validate_eth_like_address(OPERATOR_CORTEX_ADDRESS)
    )
    return {"ready": ready, "health": h}


# -----------------------------------------------------------------------------
# Mock HTTP / JSON API layer (for HuxleyGames or any web client)
# -----------------------------------------------------------------------------
def handle_api_request(
    platform: RoborunRobotankPlatform,
    method: str,
    params: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Single entry for JSON API: method name + params dict.
    Returns result dict or {"error": "..."}.
    """
    try:
        if method == "config":
            return platform.config_snapshot()
        if method == "launch_arena":
            return platform.api_launch_arena(
                params.get("caller", OPERATOR_CORTEX_ADDRESS)
            )
        if method == "get_arena":
            return platform.api_get_arena(params.get("arena_id", 0))
        if method == "advance_phase":
            return platform.api_advance_phase(
                params.get("arena_id", 0),
                params.get("caller", OPERATOR_CORTEX_ADDRESS),
            )
        if method == "assign_slot":
            return platform.api_assign_slot(
                params.get("arena_id", 0),
                params.get("player_id", ""),
                params.get("slot", 0),
                params.get("caller", OPERATOR_CORTEX_ADDRESS),
            )
        if method == "fire_turret":
            return platform.api_fire_turret(
                params.get("arena_id", 0),
                params.get("player_id", ""),
                params.get("damage", DAMAGE_PER_TURRET_FIRE),
                params.get("caller", OPERATOR_CORTEX_ADDRESS),
            )
        if method == "seed_bounty":
            return platform.api_seed_bounty(
                params.get("arena_id", 0),
                params.get("amount", 0),
                params.get("caller", OPERATOR_CORTEX_ADDRESS),
            )
        if method == "claim_bounty":
            return platform.api_claim_bounty(
                params.get("arena_id", 0),
                params.get("caller", OPERATOR_CORTEX_ADDRESS),
            )
        if method == "terminate_arena":
            return platform.api_terminate_arena(
                params.get("arena_id", 0),
                params.get("caller", OPERATOR_CORTEX_ADDRESS),
            )
        if method == "flip_pause":
            return platform.api_flip_pause(
                params.get("caller", OPERATOR_CORTEX_ADDRESS),
            )
        if method == "get_platoon_slot":
            return platform.api_get_platoon_slot(
                params.get("arena_id", 0),
                params.get("slot", 0),
            )
        if method == "get_chassis_stats":
            return platform.api_get_chassis_stats(params.get("player_id", ""))
        if method == "create_match":
            return platform.api_create_match(
                params.get("arena_id", 0),
                params.get("participant_ids", []),
                params.get("caller", OPERATOR_CORTEX_ADDRESS),
            )
        if method == "get_match":
            return platform.api_get_match(params.get("match_id", ""))
        if method == "add_match_score":
            return platform.api_add_match_score(
                params.get("match_id", ""),
                params.get("player_id", ""),
                params.get("points", 0),
            )
        if method == "finish_match":
            return platform.api_finish_match(
                params.get("match_id", ""),
                params.get("winner_player_id"),
            )
        if method == "get_or_create_player":
            return platform.api_get_or_create_player(
                params.get("player_id", ""),
                params.get("wallet_ref", ""),
            )
        if method == "get_player":
            return platform.api_get_player(params.get("player_id", ""))
        if method == "get_leaderboard":
            return platform.api_get_leaderboard(
                params.get("top_n", LEADERBOARD_TOP_N),
            )
        if method == "tick":
            return platform.api_tick()
        if method == "record_checkpoint":
            return platform.api_record_checkpoint(
                params.get("arena_id", 0),
                params.get("player_id", ""),
                params.get("distance", 0),
            )
        if method == "create_session":
            return platform.api_create_session(
                params.get("player_id", ""),
                params.get("arena_id", 0),
                params.get("match_id"),
            )
        if method == "get_session":
            return platform.api_get_session(params.get("session_id", ""))
        if method == "get_arena_summary":
            return api_get_arena_summary(
                platform,
                params.get("arena_id", 0),
            )
        if method == "get_match_summary":
            return api_get_match_summary(
                platform,
                params.get("match_id", ""),
            )
        if method == "health":
            return health_check(platform)
        if method == "readiness":
            return readiness_check(platform)
        if method == "get_constants":
            return get_all_constants()
        return {"error": f"Unknown method: {method}"}
    except ArenaEngineNotOperator as e:
        return {"error": "NotOperator", "message": str(e)}
    except ArenaEngineArenaNotFound as e:
        return {"error": "ArenaNotFound", "message": str(e)}
    except ArenaEngineArenaPaused as e:
        return {"error": "ArenaPaused", "message": str(e)}
    except ArenaEnginePhaseLocked as e:
        return {"error": "PhaseLocked", "message": str(e)}
    except ArenaEnginePlatoonFull as e:
        return {"error": "PlatoonFull", "message": str(e)}
    except ArenaEngineBatteryDepleted as e:
        return {"error": "BatteryDepleted", "message": str(e)}
    except ArenaEngineCooldownActive as e:
        return {"error": "CooldownActive", "message": str(e)}
    except ArenaEngineChassisNotFound as e:
        return {"error": "ChassisNotFound", "message": str(e)}
    except ArenaEngineMatchNotFound as e:
        return {"error": "MatchNotFound", "message": str(e)}
    except ArenaEngineMatchNotActive as e:
        return {"error": "MatchNotActive", "message": str(e)}
    except ArenaEngineInvalidAmount as e:
        return {"error": "InvalidAmount", "message": str(e)}
    except ArenaEngineZeroDisallowed as e:
        return {"error": "ZeroDisallowed", "message": str(e)}
    except Exception as e:
        return {"error": "Internal", "message": str(e)}


def list_api_methods() -> List[str]:
    """Return all supported method names for handle_api_request."""
    return [
        "config", "launch_arena", "get_arena", "advance_phase", "assign_slot",
        "fire_turret", "seed_bounty", "claim_bounty", "terminate_arena",
        "flip_pause", "get_platoon_slot", "get_chassis_stats", "create_match",
        "get_match", "add_match_score", "finish_match", "get_or_create_player",
        "get_player", "get_leaderboard", "tick", "record_checkpoint",
        "create_session", "get_session", "get_arena_summary", "get_match_summary",
        "health", "readiness", "get_constants",
    ]


def handle_batch_api_request(
    platform: RoborunRobotankPlatform,
    requests: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Process a list of {method, params} and return list of results."""
    return [
        handle_api_request(platform, r.get("method", ""), r.get("params", {}))
        for r in requests
    ]


def generate_demo_leaderboard_entries(count: int = 20) -> List[Dict[str, Any]]:
    """Generate fake leaderboard entries for UI testing (no platform state change)."""
    entries = []
    for i in range(count):
        entries.append({
            "rank": i + 1,
            "player_id": f"demo_{i}",
            "wallet_ref": PLATFORM_VAULT_ADDRESS[:18] + "..." if i % 2 == 0 else REWARD_POOL_ADDRESS[:18] + "...",
            "total_score": 1000 - i * 47 + (i % 3) * 20,
            "wins": (i + 1) % 5,
            "matches": (i + 1) * 2,
        })
    return entries


def generate_demo_arena_list(count: int = 5) -> List[Dict[str, Any]]:
    """Generate fake arena list for UI testing."""
    return [
        {
            "arena_id": j + 1,
            "phase": j % (MAX_PHASE_INDEX + 1),
            "phase_label": phase_label(j % (MAX_PHASE_INDEX + 1)),
            "terminated": False,
            "bounty_pool": 100000 * (j + 1),
            "cooldown_until": 0,
            "can_claim_bounty": j % 2 == 0,
        }
        for j in range(count)
    ]


def get_operator_address() -> str:
    return OPERATOR_CORTEX_ADDRESS


def get_vault_address() -> str:
    return PLATFORM_VAULT_ADDRESS


def get_treasury_address() -> str:
    return ARENA_TREASURY_ADDRESS


def get_reward_pool_address() -> str:
    return REWARD_POOL_ADDRESS


def get_oracle_address() -> str:
    return ORACLE_NODE_ADDRESS


def get_arena_domain_salt() -> str:
    return ARENA_DOMAIN_SALT


def get_platform_version_hash() -> str:
    return PLATFORM_VERSION_HASH


def get_chassis_mint_salt() -> str:
    return CHASSIS_MINT_SALT


def get_matchmaking_seed() -> str:
    return MATCHMAKING_SEED


def get_max_platoon_size() -> int:
    return MAX_PLATOON_SIZE


def get_arena_cooldown_ticks() -> int:
    return ARENA_COOLDOWN_TICKS


def get_phase_duration_blocks() -> int:
    return PHASE_DURATION_BLOCKS


def get_max_phase_index() -> int:
    return MAX_PHASE_INDEX


def get_bounty_base_units() -> int:
    return BOUNTY_BASE_UNITS


def get_tick_modulus() -> int:
    return TICK_MODULUS


def get_vault_share_bps() -> int:
    return VAULT_SHARE_BPS


def get_control_share_bps() -> int:
    return CONTROL_SHARE_BPS


def get_score_per_checkpoint() -> int:
    return SCORE_PER_CHECKPOINT


def get_score_per_kill() -> int:
    return SCORE_PER_KILL


def get_damage_per_turret_fire() -> int:
    return DAMAGE_PER_TURRET_FIRE


def get_default_starting_battery() -> int:
    return DEFAULT_STARTING_BATTERY


def get_battery_recharge_at_checkpoint() -> int:
    return BATTERY_RECHARGE_AT_CHECKPOINT


def get_min_battery_to_fire() -> int:
    return MIN_BATTERY_TO_FIRE


def confirm_addresses_unique() -> bool:
    """Confirm that this module uses its own address set (no cross-file reuse)."""
    addrs = [
        ARENA_TREASURY_ADDRESS,
        PLATFORM_VAULT_ADDRESS,
        REWARD_POOL_ADDRESS,
        OPERATOR_CORTEX_ADDRESS,
        ORACLE_NODE_ADDRESS,
    ]
    return len(addrs) == len(set(addrs)) and all(_validate_eth_like_address(a) for a in addrs)


def confirm_hex_salts_unique() -> bool:
    """Confirm that hex salts are unique within this module."""
    salts = [
        ARENA_DOMAIN_SALT,
        PLATFORM_VERSION_HASH,
        CHASSIS_MINT_SALT,
        MATCHMAKING_SEED,
    ]
    return len(salts) == len(set(salts)) and all(_validate_hex_salt(s, 16) for s in salts)


def format_arena_id_for_display(arena_id: int) -> str:
    """Format arena id for UI (e.g. zero-padded)."""
    return f"Arena-{arena_id:04d}"


def format_match_id_short(match_id: str) -> str:
    """Short display form of match_id."""
    return match_id[:16] + "..." if len(match_id) > 16 else match_id


def format_wallet_short(wallet: str) -> str:
    """Short wallet for UI: 0x1234...abcd."""
    if not wallet or len(wallet) < 12:
        return wallet or ""
    return f"{wallet[:6]}...{wallet[-4:]}"


def score_display(score: int) -> str:
    """Format score with commas for UI."""
    return f"{score:,}"
