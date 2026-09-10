#!/usr/bin/env python3
"""Derive compact Braille geometry/colors from the unchanged official SVG.

Run from any directory; --check verifies all generated outputs without writing.
Braille approximates the silhouette/scanline texture at terminal-cell resolution.
"""

import argparse
import re
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "packaging/client/assets/mutte-wordmark.svg"
ASSET_DIR = ROOT / "apps/mutte/assets"
MODULE = ROOT / "apps/mutte/src/wordmark.rs"
COLUMNS, ROWS, MIN_COVERAGE = 40, 3, 0.20
SAMPLES_X, SAMPLES_Y = 4, 8
NS = {"svg": "http://www.w3.org/2000/svg"}
DOTS = ((0, 0, 0), (0, 1, 1), (0, 2, 2), (1, 0, 3),
        (1, 1, 4), (1, 2, 5), (0, 3, 6), (1, 3, 7))


def source_geometry(svg):
    """The official asset consists of closed, straight-sided stripe polygons."""
    polygons = []
    for path in svg.findall("svg:path", NS):
        data = path.attrib["d"]
        if set(re.findall(r"[A-Za-z]", data)) - set("MLZ"):
            raise ValueError("Wordmark has new SVG commands; update the generator explicitly")
        for part in data.split("Z"):
            points = [tuple(map(float, point)) for point in
                      re.findall(r"[ML]([\d.]+)[ ,]+([\d.]+)", part)]
            if points:
                xs, ys = zip(*points)
                polygons.append((points, min(xs), max(xs), min(ys), max(ys)))
    if not polygons:
        raise ValueError("No official wordmark polygons found")
    return polygons


def covered(polygons, x, y):
    inside = False
    for points, x0, x1, y0, y1 in polygons:
        if not (x0 <= x <= x1 and y0 <= y <= y1):
            continue
        for (a, b), (c, d) in zip(points, points[1:] + points[:1]):
            if (b > y) != (d > y) and x < (c - a) * (y - b) / (d - b) + a:
                inside = not inside
    return inside


def artwork(svg, polygons, columns, rows, min_coverage):
    x0, y0, width, height = map(float, svg.attrib["viewBox"].split())
    dots = []
    for y in range(rows * 4):
        row = []
        for x in range(columns * 2):
            hits = sum(covered(polygons,
                               x0 + (x + (a + 0.5) / SAMPLES_X) * width / (columns * 2),
                               y0 + (y + (b + 0.5) / SAMPLES_Y) * height / (rows * 4))
                       for a in range(SAMPLES_X) for b in range(SAMPLES_Y))
            row.append(hits / (SAMPLES_X * SAMPLES_Y) >= min_coverage)
        dots.append(row)
    return "\n".join("".join(chr(0x2800 + sum(
        1 << bit for dx, dy, bit in DOTS if dots[y * 4 + dy][x * 2 + dx]))
        for x in range(columns)) for y in range(rows)) + "\n"


def gradient(svg, name, columns):
    element = svg.find("svg:defs/svg:linearGradient", NS)
    if element is None or element.attrib.get("gradientUnits") != "userSpaceOnUse":
        raise ValueError("Expected the official user-space linear gradient")
    stops = [(float(stop.attrib["offset"].rstrip("%")) / 100,
              tuple(int(stop.attrib["stop-color"][i:i + 2], 16) for i in (1, 3, 5)))
             for stop in element.findall("svg:stop", NS)]
    x1, y1, x2, y2 = (float(element.attrib[name]) for name in ("x1", "y1", "x2", "y2"))
    vx, vy = x2 - x1, y2 - y1
    bx, by, width, height = map(float, svg.attrib["viewBox"].split())
    colors = []
    for column in range(columns):
        x, y = bx + (column + 0.5) * width / columns, by + height / 2
        t = max(0.0, min(1.0, ((x - x1) * vx + (y - y1) * vy) / (vx * vx + vy * vy)))
        for (start, left), (end, right) in zip(stops, stops[1:]):
            if t <= end:
                fraction = (t - start) / (end - start)
                colors.append(tuple(round(a + (b - a) * fraction) for a, b in zip(left, right)))
                break
    if len(colors) != columns:
        raise ValueError("The official gradient must cover every terminal column")
    return f"const {name}_GRADIENT: [Color; {columns}] = [\n" + "".join(
        f"    Color::Rgb({r}, {g}, {b}),\n" for r, g, b in colors) + "];"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    svg = ET.parse(SOURCE).getroot()
    module = MODULE.read_text()
    polygons = source_geometry(svg)
    colors = gradient(svg, "COMPACT", COLUMNS)
    updated, count = re.subn(r"(?<=// BEGIN GENERATED GRADIENT\n).*?(?=\n// END GENERATED GRADIENT)",
                            colors, module, flags=re.DOTALL)
    if count != 1:
        raise ValueError("Expected one generated-gradient region in wordmark.rs")
    outputs = [(ASSET_DIR / "wordmark-terminal.txt",
                artwork(svg, polygons, COLUMNS, ROWS, MIN_COVERAGE))]
    outputs.append((MODULE, updated))
    for path, content in outputs:
        if args.check:
            if not path.exists() or path.read_text() != content:
                raise SystemExit(f"Stale generated wordmark: {path.relative_to(ROOT)}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    print("Official terminal wordmark " + ("is current" if args.check else "generated"))


if __name__ == "__main__":
    main()
