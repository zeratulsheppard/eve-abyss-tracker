"""Curated data for classifying EVE wallet transactions related to abyssal deadspace.

Names are resolved to type_ids at startup via ESI `POST /universe/ids/`. Names that
fail to resolve are logged and skipped; users can always retag manually in the UI.
"""

ABYSS_REGION_IDS = [12000001, 12000002, 12000003, 12000004, 12000005]

TRIG_LOOT_NAMES = [
    "Zero-Point Condensate",
    "Trinary State Processor",
    "Trinary Data Vault",
    "Triglavian Survey Database",
    "Enigmatic Data Vault",
    "Ancient Data Vault",
    "Extracted Isogen-5",
    "Isogen-5",
    "Assembled Antique Vindicator",
    "Assembled Antique Kronos",
    "Assembled Antique Paladin",
    "Assembled Antique Golem",
]

FILAMENT_TIERS = ["Calm", "Agitated", "Fierce", "Raging", "Chaotic", "Cataclysmic"]
FILAMENT_WEATHERS = ["Firestorm", "Electrical", "Dark", "Exotic", "Gamma"]
FILAMENT_NAMES = [
    f"{tier} {weather} Filament"
    for tier in FILAMENT_TIERS
    for weather in FILAMENT_WEATHERS
]

LOOT_NAME_SUFFIXES = ("Mutaplasmid",)
LOOT_NAME_CONTAINS = ("Isogen-5",)

DEFAULT_AMMO_NAMES = [
    "Meson Exotic Plasma S",
    "Baryon Exotic Plasma S",
    "Tetryon Exotic Plasma S",
    "Mystic S",
    "Occult S",
    "Meson Exotic Plasma M",
    "Baryon Exotic Plasma M",
    "Tetryon Exotic Plasma M",
    "Mystic M",
    "Occult M",
    "Meson Exotic Plasma L",
    "Baryon Exotic Plasma L",
    "Tetryon Exotic Plasma L",
    "Mystic L",
    "Occult L",
]
