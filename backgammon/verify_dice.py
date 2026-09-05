#!/usr/bin/env python3
"""Check the dice of a finished game of Backgammon by Arcane Void.

Needs only Python 3. Nothing is downloaded and nothing is sent anywhere.

    python3 verify_dice.py SEED SALT [ROLL ...]
    python3 verify_dice.py "SEED SALT" [ROLL ...]
    python3 verify_dice.py --seal HEX --commitment HEX SEED SALT ROLL ...

SEED and SALT are the two hex strings the game shows under "Seed revealed
at the end of the game" (64 and 32 hex digits). Paste the whole line in
quotes, or give them as two arguments.

Each ROLL is one throw of the game, in order, the opening throws first
(a tied opening throw counts as a throw). Write a roll as 31 or 3-1.
Write 7:31 to check a single throw as turn 7 (turns count from 0).

With no rolls the script prints the seal, the commitment and the first
thirty throws of the game so you can read them against the app's ledger.

Protocol (the app's dice module and this file must agree):
    seal        = SHA-256(seed || 16 zero bytes)   shown before you spin
    commitment  = SHA-256(seed || salt)            shown before the first roll
    block(t, c) = HMAC-SHA-256(key = seed, msg = salt || u32le(t) || u32le(c))
    roll t      = the first two bytes b < 252 of block(t, 0), block(t, 1), ...
                  each read as (b mod 6) + 1
Rejection of bytes 252..255 keeps every face exactly equally likely.
"""
import hashlib
import hmac
import struct
import sys


def dice(seed, salt, turn):
    """The two dice of throw `turn`, derived exactly as the app derives them."""
    out, counter = [], 0
    while len(out) < 2:
        msg = salt + struct.pack("<I", turn) + struct.pack("<I", counter)
        for b in hmac.new(seed, msg, hashlib.sha256).digest():
            if len(out) == 2:
                break
            if b < 252:
                out.append(b % 6 + 1)
        counter += 1
    return out[0], out[1]


def seal(seed):
    return hashlib.sha256(seed + bytes(16)).hexdigest()


def commitment(seed, salt):
    return hashlib.sha256(seed + salt).hexdigest()


def parse_roll(token, default_turn):
    """'31', '3-1', '3/1', '7:31' -> (turn, (3, 1))."""
    turn = default_turn
    if ":" in token:
        t, token = token.split(":", 1)
        turn = int(t)
    digits = [int(ch) for ch in token if ch.isdigit()]
    if len(digits) != 2 or not all(1 <= d <= 6 for d in digits):
        raise ValueError("roll %r must be two dice 1-6, e.g. 31 or 3-1" % token)
    return turn, (digits[0], digits[1])


def main(argv):
    want_seal = want_commit = None
    hexes, rolls = [], []
    it = iter(argv)
    for a in it:
        if a == "--seal":
            want_seal = next(it, "").lower()
        elif a == "--commitment":
            want_commit = next(it, "").lower()
        elif a in ("-h", "--help"):
            print(__doc__)
            return 2
        else:
            # the app's revealed line is "SEED SALT" in one string
            for part in a.replace(",", " ").split():
                if len(part) >= 32 and all(c in "0123456789abcdefABCDEF" for c in part):
                    hexes.append(part.lower())
                else:
                    rolls.append(part)
    if len(hexes) < 2:
        print(__doc__)
        return 2
    seed, salt = bytes.fromhex(hexes[0]), bytes.fromhex(hexes[1])
    if len(seed) != 32 or len(salt) != 16:
        print("the seed is 32 bytes (64 hex digits) and the salt 16 bytes (32 hex digits)")
        return 2
    # An older form of this script took the commitment as the third value.
    if len(hexes) >= 3 and want_commit is None:
        want_commit = hexes[2]

    ok = True
    s, c = seal(seed), commitment(seed, salt)
    print("seal (sealed before your spin) :", s, end="")
    if want_seal is not None:
        ok &= s == want_seal
        print("  MATCH" if s == want_seal else "  MISMATCH")
    else:
        print()
    print("commitment (before first roll) :", c, end="")
    if want_commit is not None:
        ok &= c == want_commit
        print("  MATCH" if c == want_commit else "  MISMATCH")
    else:
        print()
    print()

    if not rolls:
        print("first thirty throws of this game, opening throw first:")
        for t in range(30):
            a, b = dice(seed, salt, t)
            print("  turn %2d: %d-%d" % (t, a, b))
        return 0 if ok else 1

    turn = 0
    for token in rolls:
        try:
            turn, shown = parse_roll(token, turn)
        except ValueError as e:
            print(e)
            return 2
        got = dice(seed, salt, turn)
        same = got == shown
        ok &= same
        print("turn %3d: shown %d-%d  recomputed %d-%d  %s"
              % (turn, shown[0], shown[1], got[0], got[1], "ok" if same else "DIFFERENT"))
        turn += 1
    print()
    print("EVERY THROW MATCHES" if ok else "VERIFICATION FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
