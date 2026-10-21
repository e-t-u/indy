#!/usr/bin/env python3
"""Generate 16x16, 48x48, and 128x128 PNG icons for the Indy Chrome Extension."""

import os
from PIL import Image, ImageDraw


def generate_icons(output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    for size in (16, 48, 128):
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        margin = max(1, size // 16)
        radius = max(3, size // 4)

        # Dark slate-blue rounded shield background
        draw.rounded_rectangle(
            [margin, margin, size - margin - 1, size - margin - 1],
            radius=radius,
            fill=(15, 23, 42, 255),
            outline=(14, 165, 233, 255),
            width=max(1, size // 24),
        )

        # Inner shield / certificate badge polygon
        cx = size / 2.0
        top = size * 0.20
        bottom = size * 0.82
        left = size * 0.26
        right = size * 0.74
        mid_y = size * 0.56

        shield_pts = [
            (cx, top),
            (right, size * 0.28),
            (right, mid_y),
            (cx, bottom),
            (left, mid_y),
            (left, size * 0.28),
        ]
        draw.polygon(
            shield_pts,
            fill=(2, 132, 199, 255),
            outline=(56, 189, 248, 255),
        )

        # Central "I" pillar inside the shield for "Indy"
        bar_w = max(2, int(size * 0.11))
        bar_h = max(4, int(size * 0.30))
        x0 = int(cx - bar_w / 2)
        y0 = int(size * 0.35)
        draw.rectangle(
            [x0, y0, x0 + bar_w, y0 + bar_h],
            fill=(255, 255, 255, 255),
        )

        path = os.path.join(output_dir, f"icon-{size}.png")
        img.save(path, format="PNG")
        print(f"Generated {path} ({size}x{size})")


if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    generate_icons(os.path.join(base_dir, "extension", "icons"))
