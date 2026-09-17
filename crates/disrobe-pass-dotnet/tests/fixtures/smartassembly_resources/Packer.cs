using System;
using System.IO;
using System.IO.Compression;

if (args.Length != 3)
{
    return 2;
}

byte[] input = File.ReadAllBytes(args[0]);
int chunkSize = int.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture);
if (input.Length == 0 || chunkSize <= 0)
{
    return 3;
}

using FileStream output = File.Create(args[1]);
using BinaryWriter writer = new(output);
writer.Write(0x017D7A7B);
writer.Write(input.Length);
for (int offset = 0; offset < input.Length; offset += chunkSize)
{
    int length = Math.Min(chunkSize, input.Length - offset);
    using MemoryStream compressed = new();
    using (DeflateStream deflate = new(compressed, CompressionLevel.SmallestSize, true))
    {
        deflate.Write(input, offset, length);
    }
    byte[] part = compressed.ToArray();
    writer.Write(part.Length);
    writer.Write(length);
    writer.Write(part);
}

return 0;
