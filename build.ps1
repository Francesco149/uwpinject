$invocation = (Get-Variable MyInvocation).Value
$dir = Split-Path $invocation.MyCommand.Path
Write-Output "working dir: $dir"

function Write-Header {
  param ([string]$Message)
  $oldcolor = $host.UI.RawUI.ForegroundColor
  $host.UI.RawUI.ForegroundColor = "Green"
  Write-Output ":: $Message"
  $host.UI.RawUI.ForegroundColor = $oldcolor
}

Push-Location $dir
$res = $null
try {
  Write-Header "linting"
  $hasAnalyzer = Get-Command "Invoke-ScriptAnalyzer" `
    -ErrorAction SilentlyContinue
  if (-not $hasAnalyzer) {
    Write-Warning "you're missing PSScriptAnalyzer, skipping lint step"
    return
  }
  $results = Invoke-ScriptAnalyzer -Path . -Recurse
  foreach ($result in $results) {
    Write-Output ($result | Format-Table | Out-String)
  }
  if ($results.Count -ne 0) {
    Throw "did not pass ps1 linting"
  }
  New-Item dlls -ItemType directory -ErrorAction SilentlyContinue
  Get-ChildItem -file -Recurse . |
    Where-Object { $_.Name -match ".*\.c" } |
    ForEach-Object -Process {
      $target = (Get-Item $_).Basename
      Write-Header "cleaning $target"
      Remove-Item "$target.obj", "$target.exe" `
        -ErrorAction SilentlyContinue
      Write-Header "compiling $_"
      cl /nologo /EHsc /Gm- /GR- /W4 /D_CRT_SECURE_NO_WARNINGS=1 $_
      if (-not $?) {
        Throw "cl failed: $LastExitCode"
      }
    }
} catch {
  $res = $_
}
Pop-Location
if ($null -ne $res) {
  Throw $res
}
