"""Adds an English voice-over (edge-tts neural voice) and a soft generated music bed
to the captioned demo. Run after build.py."""
import json
import subprocess
from pathlib import Path

OUT = Path("D:/clocked hackson/video/out")
TTS = OUT / "tts"
VOICE = "en-US-AndrewNeural"
SRC = OUT / "preflight-demo.mp4"
FINAL = OUT / "preflight-demo-voice.mp4"

# (start second in the final cut, latest end second, line)
LINES = [
    (0.6, 7.6, "Agents now read content written by strangers. Preflight checks it before Codex reads it."),
    (8.0, 14.4, "A setup guide from a stranger. One code block quietly uploads your SSH and cloud keys."),
    (14.6, 22.6, "Preflight blocks the original, and marks the two exfiltration lines, character by character."),
    (22.8, 31.4, "The prepared copy cuts only that block, rechecks everything else, and shows the exact edit. A person must confirm."),
    (31.9, 38.8, "Now a real Codex run. Codex hands over only the file path, and gets back a ticket, not the text."),
    (39.1, 48.0, "The reviewer sees the same report and the exact copy, then approves it. The approval is bound to that copy's hash."),
    (48.3, 56.9, "Codex reads exactly the approved snapshot, and never sees the upload command."),
    (57.2, 72.9, "The same works in Chinese. An instruction hidden in a comment is found, and the copy removes only that instruction."),
    (73.3, 88.0, "Links get a receipt: who the page claims to be, what public records say, the final URL, the fetch time and a fingerprint."),
    (88.6, 97.3, "The original goes to the reviewer. Codex reads only the approved copy. That's Preflight."),
]


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def duration(path):
    return float(run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(path)]).stdout)


def synth():
    TTS.mkdir(exist_ok=True)
    clips = []
    for i, (start, end, text) in enumerate(LINES):
        mp3 = TTS / f"line{i:02d}.mp3"
        run(["uvx", "edge-tts", "--voice", VOICE, "--rate", "+4%", "--text", text, "--write-media", str(mp3)])
        d = duration(mp3)
        room = end - start
        tempo = 1.0 if d <= room else d / room
        if tempo > 1.18:
            raise SystemExit(f"line {i} is {d:.1f}s for a {room:.1f}s slot; shorten it")
        clips.append({"file": mp3, "start": start, "tempo": tempo, "spoken": d / tempo})
    return clips


def music(total):
    # soft sustained chord (Cmaj9-ish) with slow tremolo; generated, so no licensing questions
    notes = [130.81, 196.00, 246.94, 293.66, 329.63]
    expr = "+".join(f"0.16*sin(2*PI*{f}*t)" for f in notes)
    bed = OUT / "bed.wav"
    run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi",
         "-i", f"aevalsrc='({expr})*(0.75+0.25*sin(2*PI*0.08*t))':s=48000:d={total:.2f}",
         "-af", f"lowpass=f=900,aecho=0.8:0.7:120|260:0.25|0.18,afade=t=in:d=2,afade=t=out:st={total - 3:.2f}:d=3,volume=0.32",
         "-ac", "2", str(bed)])
    return bed


def main():
    total = duration(SRC)
    clips = synth()
    bed = music(total)
    inputs, chains = ["-i", str(SRC), "-i", str(bed)], []
    for k, c in enumerate(clips):
        inputs += ["-i", str(c["file"])]
        idx = k + 2
        tempo = f"atempo={c['tempo']:.3f}," if c["tempo"] > 1 else ""
        chains.append(f"[{idx}:a]{tempo}aresample=48000,adelay={int(c['start'] * 1000)}:all=1[v{k}]")
    mix = "".join(f"[v{k}]" for k in range(len(clips)))
    graph = ";".join(chains) + (
        f";{mix}amix=inputs={len(clips)}:normalize=0,volume=1.6[voice]"
        ";[voice]asplit=2[vo][sc]"
        ";[1:a][sc]sidechaincompress=threshold=0.03:ratio=8:attack=20:release=400[duck]"
        ";[vo][duck]amix=inputs=2:normalize=0,alimiter=limit=0.9[aout]")
    run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", *inputs, "-filter_complex", graph,
         "-map", "0:v", "-map", "[aout]", "-c:v", "copy", "-c:a", "aac", "-b:a", "160k",
         "-t", f"{total:.3f}", "-movflags", "+faststart", str(FINAL)])
    print(json.dumps([{"start": c["start"], "spoken": round(c["spoken"], 2), "tempo": round(c["tempo"], 3)} for c in clips]))
    print(FINAL)


if __name__ == "__main__":
    main()
