"""Generates a rhythmic music bed (104 BPM, Am-F-C-G) that follows the demo's sections.
usage: uv run --no-project --with numpy --with scipy python -I video/music.py <seconds> <out.wav>"""
import sys
import wave

import numpy as np
from scipy.signal import butter, lfilter

SR = 48000
BPM = 104
BEAT = 60 / BPM
STEP = BEAT / 4  # sixteenth note
rng = np.random.default_rng(7)

# section starts in the final cut: intro, scans, Codex handoff, Chinese + URL, outro
SECTIONS = [(0.0, "intro"), (7.8, "full"), (31.9, "groove"), (57.2, "full"), (88.6, "outro")]
LEVELS = {  # per-element gain in each section
    "intro":  dict(kick=0.0, clap=0.0, hat=0.7, bass=0.0, arp=0.8, pad=1.0),
    "full":   dict(kick=1.0, clap=1.0, hat=1.0, bass=1.0, arp=1.0, pad=0.8),
    "groove": dict(kick=0.8, clap=0.0, hat=0.9, bass=0.9, arp=1.0, pad=0.7),
    "outro":  dict(kick=0.0, clap=0.0, hat=0.5, bass=0.0, arp=0.8, pad=1.0),
}
CHORDS = [  # root (bass) and arpeggio notes, MIDI numbers
    (45, [57, 60, 64, 67]),  # Am7
    (41, [53, 57, 60, 64]),  # Fmaj7
    (48, [55, 60, 64, 67]),  # C
    (43, [55, 59, 62, 67]),  # G
]


def hz(m):
    return 440.0 * 2 ** ((m - 69) / 12)


def section_at(t):
    name = SECTIONS[0][1]
    for start, n in SECTIONS:
        if t >= start:
            name = n
    return name


def lp(x, f, order=2):
    b, a = butter(order, f / (SR / 2), "low")
    return lfilter(b, a, x)


def hp(x, f, order=2):
    b, a = butter(order, f / (SR / 2), "high")
    return lfilter(b, a, x)


def add(buf, start, sig, gain=1.0):
    i = int(start * SR)
    if i >= len(buf):
        return
    n = min(len(sig), len(buf) - i)
    buf[i:i + n] += sig[:n] * gain


def saw(f, n, detune=0.0):
    t = np.arange(n) / SR
    return 2 * ((t * f * (1 + detune)) % 1.0) - 1


def main():
    total = float(sys.argv[1])
    out = sys.argv[2]
    n = int(total * SR)
    L = np.zeros(n)
    R = np.zeros(n)
    kick_env = np.zeros(n)  # drives the sidechain "pump" on bass and pad

    # one-shot drum sounds
    kt = np.arange(int(0.45 * SR)) / SR
    kick = np.sin(2 * np.pi * np.cumsum(45 + 95 * np.exp(-kt * 28)) / SR) * np.exp(-kt * 7.5)
    kick += 0.3 * np.exp(-kt * 60) * rng.standard_normal(len(kt)) * 0.15
    ct = np.arange(int(0.25 * SR)) / SR
    clap = hp(lp(rng.standard_normal(len(ct)), 3500), 900) * (np.exp(-ct * 22) + 0.6 * np.exp(-((ct - 0.012) ** 2) / 1e-5))
    ht = np.arange(int(0.07 * SR)) / SR
    hat = hp(rng.standard_normal(len(ht)), 7000, 4) * np.exp(-ht * 70)

    steps = int(total / STEP) + 1
    for s in range(steps):
        t = s * STEP
        lv = LEVELS[section_at(t)]
        beat_in_bar, sub = divmod(s % 16, 4)
        bar = s // 16
        root, arp_notes = CHORDS[bar % 4]
        if sub == 0 and lv["kick"]:
            add(L, t, kick, 0.9 * lv["kick"]); add(R, t, kick, 0.9 * lv["kick"])
            add(kick_env, t, np.exp(-np.arange(int(0.3 * SR)) / SR * 9))
        if sub == 0 and beat_in_bar in (1, 3) and lv["clap"]:
            add(L, t, clap, 0.32 * lv["clap"]); add(R, t, clap, 0.32 * lv["clap"])
        if sub == 2 and lv["hat"]:  # off-beat open-ish hat
            add(L, t, hat, 0.20 * lv["hat"]); add(R, t, hat, 0.26 * lv["hat"])
        elif lv["hat"]:
            add(L, t, hat, 0.08 * lv["hat"]); add(R, t, hat, 0.06 * lv["hat"])
        if sub in (0, 2) and lv["bass"]:  # eighth-note bass, octave jump on the "and" of 4
            m = root + (12 if (beat_in_bar == 3 and sub == 2) else 0)
            nn = int(STEP * 1.8 * SR)
            env = np.minimum(1, np.arange(nn) / (0.004 * SR)) * np.exp(-np.arange(nn) / SR * 6)
            b = lp(saw(hz(m), nn) + 0.6 * np.sin(2 * np.pi * hz(m) * np.arange(nn) / SR), 420) * env
            add(L, t, b, 0.34 * lv["bass"]); add(R, t, b, 0.34 * lv["bass"])
        if lv["arp"]:  # sixteenth arpeggio with ping-pong delay
            m = arp_notes[[0, 1, 2, 3, 2, 1, 3, 2][s % 8]] + 12
            nn = int(0.22 * SR)
            env = np.exp(-np.arange(nn) / SR * 18)
            p = lp(saw(hz(m), nn) + saw(hz(m), nn, 0.004), 2600) * env * 0.075 * lv["arp"]
            add(L, t, p); add(R, t, p, 0.7)
            add(R, t + STEP * 3, p, 0.45); add(L, t + STEP * 6, p, 0.25)

    # pad: one sustained chord per bar, detuned saws, slow attack
    bar_len = BEAT * 4
    for bar in range(int(total / bar_len) + 1):
        t = bar * bar_len
        lv = LEVELS[section_at(t)]
        _, notes = CHORDS[bar % 4]
        nn = int(bar_len * SR) + int(0.3 * SR)
        x = np.arange(nn) / SR
        env = np.minimum(1, x / 0.35) * np.minimum(1, np.maximum(0, (bar_len + 0.3 - x) / 0.3))
        sig = sum(saw(hz(m), nn, d) for m in notes for d in (-0.003, 0.003))
        sig = lp(sig, 1400) * env * 0.035 * lv["pad"]
        add(L, t, sig); add(R, t, sig)

    # sidechain pump: bass and pad dip with each kick (applied to the whole bed lightly)
    pump = 1 - 0.28 * np.clip(kick_env, 0, 1)
    L *= pump; R *= pump

    # fade in/out, gentle bus glue
    fade = np.ones(n)
    fi, fo = int(1.0 * SR), int(4.0 * SR)
    fade[:fi] = np.linspace(0, 1, fi)
    fade[-fo:] = np.linspace(1, 0, fo)
    L *= fade; R *= fade
    st = np.stack([L, R], axis=1)
    st = np.tanh(st * 1.3) / np.tanh(1.3)
    rms = np.sqrt(np.mean(st ** 2))
    st *= 0.14 / rms  # about -17 dBFS RMS
    st = np.clip(st, -0.98, 0.98)
    with wave.open(out, "wb") as w:
        w.setnchannels(2); w.setsampwidth(2); w.setframerate(SR)
        w.writeframes((st * 32767).astype("<i2").tobytes())


if __name__ == "__main__":
    main()
