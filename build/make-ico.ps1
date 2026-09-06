# Собирает мультиразмерный .ico из исходного PNG.
# Используем PNG-encoded ICO entries (поддерживается Vista+).
param(
    [string]$Source = (Join-Path $PSScriptRoot '..\icon.png'),
    [string]$Output = (Join-Path $PSScriptRoot 'icon.ico')
)

Add-Type -AssemblyName System.Drawing

$sizes = @(16, 24, 32, 48, 64, 128, 256)

$src = [System.Drawing.Image]::FromFile((Resolve-Path $Source))

$pngData = @()
foreach ($size in $sizes) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)
    $g.DrawImage($src, 0, 0, $size, $size)
    $g.Dispose()

    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    $pngData += , $ms.ToArray()
}
$src.Dispose()

$fs = [System.IO.File]::Open($Output, [System.IO.FileMode]::Create)
$bw = New-Object System.IO.BinaryWriter $fs

$bw.Write([uint16]0)          # reserved
$bw.Write([uint16]1)          # type = icon
$bw.Write([uint16]$sizes.Count)

$offset = 6 + (16 * $sizes.Count)
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $size = $sizes[$i]
    $data = $pngData[$i]
    $w = if ($size -eq 256) { 0 } else { $size }
    $h = if ($size -eq 256) { 0 } else { $size }
    $bw.Write([byte]$w)
    $bw.Write([byte]$h)
    $bw.Write([byte]0)         # colors
    $bw.Write([byte]0)         # reserved
    $bw.Write([uint16]1)       # planes
    $bw.Write([uint16]32)      # bit count
    $bw.Write([uint32]$data.Length)
    $bw.Write([uint32]$offset)
    $offset += $data.Length
}

foreach ($data in $pngData) {
    $bw.Write($data)
}

$bw.Flush()
$bw.Close()
$fs.Close()

Write-Output "Created: $Output ($((Get-Item $Output).Length) bytes, $($sizes.Count) sizes)"
