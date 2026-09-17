# Display font sources

The display fonts below were obtained from the Google Fonts source repository on
2026-09-07. Their original SIL Open Font License texts are retained beside them.
The renderer verifies the vendored bytes before exporting typography as SVG paths.

| Font | Source | License file | SHA-256 |
| --- | --- | --- | --- |
| Barlow Condensed Bold | [Google Fonts](https://github.com/google/fonts/tree/main/ofl/barlowcondensed) | `BarlowCondensed-OFL.txt` | `e476562ec9c1e16cf16475895b511f08c804f438cc9a9f80a44ea50a0eeb5b65` |
| Archivo Black Regular | [Google Fonts](https://github.com/google/fonts/tree/main/ofl/archivoblack) | `ArchivoBlack-OFL.txt` | `dd9a89a019b4849f66ab75455fe7bdf931311042cbb0f0f97acc061539703180` |
| Manrope variable | [Google Fonts](https://github.com/google/fonts/tree/main/ofl/manrope) | `Manrope-OFL.txt` | `d0639be45d0af36e798172419d7bd173c4bd4f29e2b76cbb69db1d11bf8b0a40` |

Inter and JetBrains Mono were already vendored in the repository. Their original
license files and byte checks remain in place. Section uses Manrope at weight 200
for the wordmark. Raster exports also load static 400 and 600 instances because the
pinned renderer uses a variable font's default outline.

The static instances were generated from the pinned Manrope.ttf with FontTools
4.64.0, using instantiateVariableFont with wght 400 or 600, static=True,
updateFontNames=True, and timestamp recalculation disabled.

| Instance | SHA-256 |
| --- | --- |
| Manrope-Regular.ttf | 7444846ec6be4a0d80b36f24cecc98a5ca853261df939595f68ac7f2772bbb7b |
| Manrope-SemiBold.ttf | 6e9631fe841ba6fbea5bcf02a3587f48823841e9d21a2cf76167ad5c9632f1e1 |
