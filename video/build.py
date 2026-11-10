"""Cut, speed up scan waits, add fades and burn English captions into the final demo."""
import json
import subprocess
from pathlib import Path

OUT = Path("D:/clocked hackson/video/out")
FINAL = OUT / "preflight-demo.mp4"

# (source, [(start, end, speed)]) ; waits for live Clocked scans are sped up and labelled
SEGMENTS = [
    ("intro", [(0, 7.8, 1)]),
    ("setup", [(1.0, 6.0, 1), (6.0, 15.4, 6), (15.4, 32.6, 1)]),
    ("codex-a", [(0, 7.3, 1)]),
    ("review", [(0, 9.2, 1)]),
    ("codex-b", [(0, 8.9, 1)]),
    ("zh", [(0, 3.0, 1), (3.0, 12.7, 5), (12.7, 23.8, 1)]),
    ("url", [(0, 3.3, 1), (3.3, 37.9, 16), (37.9, 47.6, 1)]),
    ("outro", [(0, 9.3, 1)]),
]

# captions per source, in source-time seconds (mapped through the cuts below)
CAPTIONS = {
    "setup": [
        (1.0, 6.0, "A setup guide from a stranger. It looks ordinary, but one fenced block packs ~/.ssh and ~/.aws and uploads them."),
        (6.0, 15.4, "Live Clocked scan: Guard, Protect, routing, Inspect, Decide, then a full recheck of the copy (sped up)"),
        (15.6, 19.4, "Verdict BLOCK. The local policy keeps the floor: a high-severity malicious script blocks the original."),
        (19.4, 23.8, "Character-exact evidence: the two exfiltration lines are marked as a malicious script."),
        (23.8, 27.6, "The prepared copy cuts only that fenced block. Everything else is kept and rechecked."),
        (27.6, 32.6, "Compare edits shows the exact original span next to its replacement. A person must confirm."),
    ],
    "codex-a": [
        (0.3, 7.3, "Now a real Codex run. Codex passes only the path to preflight_open. It receives a ticket, not the text."),
    ],
    "review": [
        (0.2, 4.4, "The person opens the review link: the same report, and the exact copy Codex would receive."),
        (4.4, 9.2, "They confirm and approve. The server binds the approval to this version and its SHA-256."),
    ],
    "codex-b": [
        (0.2, 4.5, "preflight_read releases exactly the approved snapshot, with the risky block replaced by a marker."),
        (4.5, 8.9, "Codex works from the checked copy and never saw or ran the upload command."),
    ],
    "zh": [
        (0.2, 3.0, "Indirect injection, in Chinese: a project update hides an instruction for the AI inside an HTML comment."),
        (3.0, 12.7, "Live scan (sped up)"),
        (12.9, 16.6, "BLOCK. Guard marks the hidden instruction, Protect marks the attacker's address."),
        (16.6, 23.8, "The copy removes only the instruction, right after the emoji, and the rest is rechecked."),
    ],
    "url": [
        (0.2, 3.3, "Links get a receipt too. Here: the official QQ Music download page, fetched live without running its JavaScript."),
        (3.3, 37.9, "Live fetch, identity lookups and scan (sped up)"),
        (38.0, 42.0, "Identity: the page claims QQ Music, and public records list qq.com as an official domain."),
        (42.0, 47.6, "The receipt keeps the requested and final URL, the fetch time and the SHA-256 of the page."),
    ],
}

FADE = 0.35


def run(cmd):
    subprocess.run(cmd, check=True)


def build_parts():
    parts, mapping, t = [], {}, 0.0
    for name, cuts in SEGMENTS:
        src = OUT / f"{name}.mp4"
        mapping[name] = []
        for k, (a, b, speed) in enumerate(cuts):
            dur = (b - a) / speed
            part = OUT / f"part_{name}_{k}.mp4"
            vf = f"trim={a}:{b},setpts=(PTS-STARTPTS)/{speed},fps=30"
            if k == 0:
                vf += f",fade=t=in:st=0:d={FADE}"
            if k == len(cuts) - 1:
                vf += f",fade=t=out:st={max(0, dur - FADE):.3f}:d={FADE}"
            run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-i", str(src), "-vf", vf,
                 "-an", "-c:v", "libx264", "-crf", "18", "-pix_fmt", "yuv420p", str(part)])
            mapping[name].append((a, b, speed, t))
            parts.append(part)
            t += dur
    return parts, mapping, t


def to_final(mapping, name, x):
    for a, b, speed, start in mapping[name]:
        if a <= x <= b:
            return start + (x - a) / speed
    a, b, speed, start = mapping[name][-1]
    return start + (b - a) / speed


def ass_time(s):
    h, rem = divmod(max(0.0, s), 3600)
    m, sec = divmod(rem, 60)
    return f"{int(h)}:{int(m):02d}:{sec:05.2f}"


def write_ass(mapping):
    head = """[Script Info]
ScriptType: v4.00+
PlayResX: 1920
PlayResY: 1080
WrapStyle: 0

[V4+ Styles]
Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding
Style: Cap,Segoe UI Semibold,40,&H00FFFFFF,&H00FFFFFF,&H00000000,&H2E18181B,0,0,0,0,100,100,0,0,3,18,0,2,160,160,56,1

[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
"""
    lines = []
    for name, caps in CAPTIONS.items():
        for a, b, text in caps:
            s, e = to_final(mapping, name, a), to_final(mapping, name, b)
            lines.append(f"Dialogue: 0,{ass_time(s + 0.05)},{ass_time(e - 0.1)},Cap,,0,0,0,,{{\\fad(180,180)}}{text}")
    path = OUT / "captions.ass"
    path.write_text(head + "\n".join(lines) + "\n", encoding="utf-8")
    return path


def main():
    parts, mapping, total = build_parts()
    listing = OUT / "parts.txt"
    listing.write_text("".join(f"file '{p.name}'\n" for p in parts), encoding="utf-8")
    joined = OUT / "joined.mp4"
    run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "concat", "-safe", "0", "-i", str(listing),
         "-c", "copy", str(joined)])
    write_ass(mapping)
    # libass filter paths: run from OUT so a relative name avoids drive-letter escaping
    subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-i", "joined.mp4",
                    "-f", "lavfi", "-t", f"{total:.3f}", "-i", "anullsrc=r=48000:cl=stereo",
                    "-vf", "ass=captions.ass", "-map", "0:v", "-map", "1:a", "-shortest",
                    "-c:v", "libx264", "-crf", "20", "-preset", "slow", "-pix_fmt", "yuv420p",
                    "-c:a", "aac", "-b:a", "96k", "-movflags", "+faststart", FINAL.name],
                   check=True, cwd=OUT)
    print(json.dumps({"seconds": round(total, 1), "file": str(FINAL)}))


if __name__ == "__main__":
    main()
