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
