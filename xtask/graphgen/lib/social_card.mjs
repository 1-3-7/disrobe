import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { Resvg } from "@resvg/resvg-js";

const WIDTH = 1280;
const HEIGHT = 640;
const FONT_SPECS = [
  [
    new URL("../fonts/BarlowCondensed-Bold.ttf", import.meta.url),
    "e476562ec9c1e16cf16475895b511f08c804f438cc9a9f80a44ea50a0eeb5b65",
  ],
  [
    new URL("../fonts/ArchivoBlack-Regular.ttf", import.meta.url),
    "dd9a89a019b4849f66ab75455fe7bdf931311042cbb0f0f97acc061539703180",
  ],
  [
    new URL("../fonts/Manrope.ttf", import.meta.url),
    "d0639be45d0af36e798172419d7bd173c4bd4f29e2b76cbb69db1d11bf8b0a40",
  ],
  [
    new URL("../fonts/Manrope-Regular.ttf", import.meta.url),
    "7444846ec6be4a0d80b36f24cecc98a5ca853261df939595f68ac7f2772bbb7b",
  ],
  [
    new URL("../fonts/Manrope-SemiBold.ttf", import.meta.url),
    "6e9631fe841ba6fbea5bcf02a3587f48823841e9d21a2cf76167ad5c9632f1e1",
  ],
  [
    new URL("../fonts/JetBrainsMono-Regular.ttf", import.meta.url),
    "a0bf60ef0f83c5ed4d7a75d45838548b1f6873372dfac88f71804491898d138f",
  ],
  [
    new URL("../fonts/JetBrainsMono-SemiBold.ttf", import.meta.url),
    "1b3bfa1ed5665a4ce3f9feb68d2d4e40e70bf8b4b7d9a3edd418f321b4e166a0",
  ],
  [
    new URL("../fonts/JetBrainsMono-Bold.ttf", import.meta.url),
    "5590990c82e097397517f275f430af4546e1c45cff408bde4255dad142479dcb",
  ],
  [
    new URL("../fonts/Inter-Regular.ttf", import.meta.url),
    "40d692fce188e4471e2b3cba937be967878f631ad3ebbbdcd587687c7ebe0c82",
  ],
];

export function vendoredFontFiles() {
  return FONT_SPECS.map(([url, expectedHash]) => {
    const path = fileURLToPath(url);
    const bytes = readFileSync(path);
    const actualHash = createHash("sha256").update(bytes).digest("hex");
    if (actualHash !== expectedHash) {
      throw new Error(
        `vendored font ${path} has sha256:${actualHash}, expected sha256:${expectedHash}`,
      );
    }
    return path;
  });
}

export function renderSocialCard(svg, fontFiles) {
  if (!Buffer.isBuffer(svg) && typeof svg !== "string") {
    throw new TypeError("social-card SVG must be a Buffer or string");
  }
  if (!Array.isArray(fontFiles) || fontFiles.length !== FONT_SPECS.length) {
    throw new TypeError(
      `social-card renderer requires ${FONT_SPECS.length} pinned font files`,
    );
  }
  const renderer = new Resvg(svg, {
    background: "#0a0a0a",
    fitTo: { mode: "width", value: WIDTH },
    font: {
      cursiveFamily: "Manrope",
      defaultFontFamily: "JetBrains Mono",
      fantasyFamily: "Manrope",
      fontFiles,
      loadSystemFonts: false,
      monospaceFamily: "JetBrains Mono",
      sansSerifFamily: "Manrope",
      serifFamily: "Manrope",
    },
    imageRendering: 0,
    logLevel: "error",
    shapeRendering: 2,
    textRendering: 2,
  });
  const rendered = renderer.render();
  if (rendered.width !== WIDTH || rendered.height !== HEIGHT) {
    throw new Error(
      `social-card renderer produced ${rendered.width}x${rendered.height}, expected ${WIDTH}x${HEIGHT}`,
    );
  }
  return rendered.asPng();
}
