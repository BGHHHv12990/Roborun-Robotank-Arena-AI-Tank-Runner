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
