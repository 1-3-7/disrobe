# PHP

The FOSS landscape for PHP encoders is essentially nothing - the dominant tools are paid, server-side upload services. **disrobe** decodes the common encoders fully offline.

```sh
disrobe php decode payload.php --out clean.php       # phar / ionCube / SourceGuardian / ZendGuard
disrobe php peel chained.php --out clean.php          # eval() / base64_decode / gzinflate chains
disrobe php phar archive.phar --out extracted/        # Phar manifest walker
```

`decode` performs structural decode of ionCube, SourceGuardian, and Zend Guard envelopes plus Phar. `peel` unwraps `eval()` / `base64_decode` / `gzinflate` chains until the residue is plain PHP. Nothing is uploaded anywhere - the decode is entirely local.
