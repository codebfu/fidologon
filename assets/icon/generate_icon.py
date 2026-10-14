"""Generates the FidoLogon icon: a security key whose touch pad emits contact waves.

Outputs (next to this script):
  fidologon.ico      application icon (16 to 256 px, simplified drawing at small sizes)
  fidologon-256.png  preview / README image
and native/credential_provider/tile_image.png + tile_image.bmp, the 128x128 sign-in option glyph
(white, transparent),
and installer/banner.bmp + installer/dialog.bmp, the WixUI page bitmaps.

Requires Pillow. Run: python assets/icon/generate_icon.py
"""

import io
import struct
from pathlib import Path

from PIL import Image, ImageDraw

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent

ICO_SIZES = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]
SUPERSAMPLE = 8

BLUE_TOP = (26, 115, 209)
BLUE_BOTTOM = (0, 84, 166)  # same blue as the original sign-in tile
WHITE = (255, 255, 255)
GOLD = (242, 184, 48)
GOLD_DARK = (196, 140, 20)
CONNECTOR = (214, 222, 232)
SLOT = (120, 132, 148)


def gradient(size, top, bottom):
    image = Image.new("RGBA", (size, size))
    draw = ImageDraw.Draw(image)
    for y in range(size):
        t = y / max(size - 1, 1)
        color = tuple(round(a + (b - a) * t) for a, b in zip(top, bottom))
        draw.line([(0, y), (size, y)], fill=color + (255,))
    return image


def draw_key(draw, s, scale, offset, waves):
    """Draws the key on a 1024-unit grid, scaled by `scale` and shifted by `offset` (pixels)."""

    def p(x, y):
        return (offset[0] + x * scale, offset[1] + y * scale)

    def box(x0, y0, x1, y1):
        return [p(x0, y0), p(x1, y1)]

    # USB connector, behind the body.
    draw.rounded_rectangle(box(690, 400, 905, 624), radius=28 * scale, fill=CONNECTOR)
    if waves > 0:
        draw.rectangle(box(780, 450, 830, 490), fill=SLOT)
        draw.rectangle(box(780, 534, 830, 574), fill=SLOT)
    # Key body.
    draw.rounded_rectangle(box(120, 312, 730, 712), radius=120 * scale, fill=WHITE)
    # Touch pad.
    cx, cy = 425, 512
    pad = 92 if waves else 120
    draw.ellipse(box(cx - pad, cy - pad, cx + pad, cy + pad), fill=GOLD)
    if waves:
        ring = 26
        draw.ellipse(box(cx - pad + ring, cy - pad + ring, cx + pad - ring, cy + pad - ring), fill=GOLD_DARK)
        draw.ellipse(box(cx - pad + 2 * ring, cy - pad + 2 * ring, cx + pad - 2 * ring, cy + pad - 2 * ring),
                     fill=GOLD)
    # Contact waves on both sides of the pad: "(( o ))".
    width = round(34 * scale)
    for radius in [150, 212][:waves]:
        bounds = box(cx - radius, cy - radius, cx + radius, cy + radius)
        draw.arc(bounds, 140, 220, fill=BLUE_BOTTOM, width=width)
        draw.arc(bounds, -40, 40, fill=BLUE_BOTTOM, width=width)


def render_icon(size):
    """Rounded-square application icon; fewer details at small sizes so it stays legible."""
    s = size * SUPERSAMPLE
    image = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    mask = Image.new("L", (s, s), 0)
    margin = s * 0.03
    ImageDraw.Draw(mask).rounded_rectangle([margin, margin, s - margin, s - margin], radius=s * 0.22, fill=255)
    image.paste(gradient(s, BLUE_TOP, BLUE_BOTTOM), (0, 0), mask)
    waves = 0 if size <= 24 else 1 if size <= 40 else 2
    scale = s / 1024 * (1.06 if size <= 24 else 1.0)
    offset = ((s - 1024 * scale) / 2 + s * 0.005, (s - 1024 * scale) / 2)
    draw_key(ImageDraw.Draw(image), s, scale, offset, waves)
    return image.resize((size, size), Image.LANCZOS)


def render_tile(size=128):
    """Sign-in option glyph: white outline on transparent, like the built-in Windows options.

    LogonUI shows it at about 24 px, so the key is drawn diagonally to fill the square, with
    strokes that stay about 2 px thick once scaled down.
    """
    s = size * SUPERSAMPLE
    k = s / 128
    white = (255, 255, 255, 255)
    # Drawn horizontally on a 128-unit grid, then turned by 45 degrees around the centre.
    flat = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(flat)

    def box(x0, y0, x1, y1):
        return [x0 * k, y0 * k, x1 * k, y1 * k]

    stroke = round(8 * k)
    # Key body and USB connector (outlines), centred on (64, 64).
    draw.rounded_rectangle(box(0, 38, 98, 90), radius=20 * k, outline=white, width=stroke)
    draw.rounded_rectangle(box(93, 50, 126, 78), radius=5 * k, outline=white, width=stroke)
    # Touch pad.
    cx, cy = 42, 64
    draw.ellipse(box(cx - 11, cy - 11, cx + 11, cy + 11), fill=white)
    image = flat.rotate(45, resample=Image.BICUBIC, center=(s / 2, s / 2))
    return image.resize((size, size), Image.LANCZOS)


def write_argb_bmp(path, image):
    """32-bit BMP with premultiplied alpha, as LoadImage(LR_CREATEDIBSECTION) and LogonUI expect."""
    width, height = image.size
    pixels = bytearray()
    for y in range(height - 1, -1, -1):  # bottom-up rows
        for x in range(width):
            r, g, b, a = image.getpixel((x, y))
            pixels += bytes((b * a // 255, g * a // 255, r * a // 255, a))
    header = struct.pack("<IiiHHIIiiII", 40, width, height, 1, 32, 0, len(pixels), 2835, 2835, 0, 0)
    file_header = struct.pack("<2sIHHI", b"BM", 14 + len(header) + len(pixels), 0, 0, 14 + len(header))
    path.write_bytes(file_header + header + bytes(pixels))


def render_installer_banner():
    """WixUIBannerBmp: top strip of the installer pages (493x58, text on the left)."""
    image = Image.new("RGB", (493, 58), WHITE)
    icon = render_icon(48)
    image.paste(icon, (493 - 48 - 8, 5), icon)
    return image


def render_installer_dialog():
    """WixUIDialogBmp: welcome and finish pages (493x312, artwork in the left 164 px)."""
    image = Image.new("RGB", (493, 312), WHITE)
    panel = gradient(164 * SUPERSAMPLE, BLUE_TOP, BLUE_BOTTOM).resize((164, 312))
    image.paste(panel.convert("RGB"), (0, 0))
    icon = render_icon(112)
    image.paste(icon, ((164 - 112) // 2, 70), icon)
    return image


def write_ico(path, images):
    """Writes a multi-resolution .ico with one PNG-compressed entry per image (Vista+ format)."""
    entries = []
    for image in images:
        buffer = io.BytesIO()
        image.save(buffer, format="PNG", optimize=True)
        entries.append((image.width, buffer.getvalue()))
    header = struct.pack("<HHH", 0, 1, len(entries))
    offset = len(header) + 16 * len(entries)
    directory = b""
    for width, data in entries:
        dim = 0 if width >= 256 else width
        directory += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    path.write_bytes(header + directory + b"".join(data for _, data in entries))


def main():
    icons = [render_icon(size) for size in ICO_SIZES]
    write_ico(HERE / "fidologon.ico", icons)
    icons[-1].save(HERE / "fidologon-256.png", optimize=True)
    tile = render_tile()
    write_argb_bmp(ROOT / "native" / "credential_provider" / "tile_image.bmp", tile)
    tile.save(ROOT / "native" / "credential_provider" / "tile_image.png", optimize=True)
    render_installer_banner().save(ROOT / "installer" / "banner.bmp")
    render_installer_dialog().save(ROOT / "installer" / "dialog.bmp")
    print("Wrote fidologon.ico, fidologon-256.png, the tile glyph and the installer bitmaps")


if __name__ == "__main__":
    main()
