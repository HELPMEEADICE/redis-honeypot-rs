# Empirical flood check against the release binary.
# Measures: empty-element flood behaviour, oversized value refusal, working set.
# The helper takes and returns plain strings only: binding arrays through
# PowerShell parameters is a trap, and this needs no such cleverness.
$ErrorActionPreference = 'Stop'
$exe  = Join-Path (Get-Location) 'target\release\redis-honeypot-rs.exe'
$db   = Join-Path $env:TEMP ("rhp-flood-{0}.db" -f $PID)
$port = 16385
Remove-Item "$db*" -ErrorAction SilentlyContinue

$script:port = $port
$script:buffer = New-Object byte[] 16384

function Invoke-Flood([string] $payloadText, [int] $expectLines) {
    $client = [System.Net.Sockets.TcpClient]::new()
    $client.Connect('127.0.0.1', $script:port)
    $stream = $client.GetStream()
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($payloadText)
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()

    $text = ''
    $readError = ''
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ([DateTime]::UtcNow -lt $deadline) {
        try { $n = $stream.Read($script:buffer, 0, $script:buffer.Length) }
        catch { $readError = 'reset'; break }
        if ($n -le 0) { $readError = 'eof'; break }
        $text += [System.Text.Encoding]::ASCII.GetString($script:buffer, 0, $n)
        if (($text -split "`r`n").Count - 1 -ge $expectLines) { break }
    }
    $client.Close()
    return @{ text = $text; error = $readError }
}

$proc = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden -ArgumentList @(
    'serve','--bind',"127.0.0.1:$port",'--db',$db,'--min-delay','10','--max-delay','20'
)
try {
    Start-Sleep -Milliseconds 900
    if ($proc.HasExited) { throw "server exited: $($proc.ExitCode)" }
    $proc.Refresh()
    $idle = $proc.WorkingSet64

    # ---- scenario 1: empty-string list flood (the old unbounded path) -----
    $one = "*3`r`n`$5`r`nRPUSH`r`n`$5`r`nflood`r`n`$0`r`n`r`n"
    $r1 = Invoke-Flood ($one * 1000) 1000
    $listOk  = ([regex]::Matches($r1.text, '(?m)^:\d+')).Count
    $listErr = ([regex]::Matches($r1.text, '(?m)^-ERR')).Count
    $listFirstError = ([regex]::Match($r1.text, '(?m)^-ERR.*$')).Value
    $proc.Refresh(); $afterList = $proc.WorkingSet64

    # ---- scenario 2: repeated oversized single values ---------------------
    $big = 'x' * 5000
    $parts = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt 1000; $i++) {
        $key = "k$i"
        # Bulk headers must carry the real length: build them with -f, because a
        # backtick-escaped `` `$ `` does not interpolate a subexpression.
        $parts.Add(("*3`r`n`$3`r`nSET`r`n`${0}`r`n{1}`r`n`${2}`r`n{3}`r`n" -f $key.Length, $key, $big.Length, $big))
    }
    $r2 = Invoke-Flood ($parts -join '') 1000
    $bigOk  = ([regex]::Matches($r2.text, '(?m)^\+OK')).Count
    $bigErr = ([regex]::Matches($r2.text, '(?m)^-ERR')).Count
    $bigFirstError = ([regex]::Match($r2.text, '(?m)^-ERR.*$')).Value
    $proc.Refresh(); $afterBig = $proc.WorkingSet64

    # ---- scenario 3: many distinct keys, global budget must hold ----------
    $value = 'y' * 400
    $parts = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt 900; $i++) {
        $key = "key:{0:D4}" -f $i
        $parts.Add(("*3`r`n`$3`r`nSET`r`n`${0}`r`n{1}`r`n`${2}`r`n{3}`r`n" -f $key.Length, $key, $value.Length, $value))
    }
    $r3 = Invoke-Flood ($parts -join '') 900
    $keysOk = ([regex]::Matches($r3.text, '(?m)^\+OK')).Count
    $proc.Refresh(); $afterKeys = $proc.WorkingSet64

    [pscustomobject]@{
        idle_mib           = [math]::Round($idle / 1MB, 2)
        after_list_flood   = [math]::Round($afterList / 1MB, 2)
        after_big_values   = [math]::Round($afterBig / 1MB, 2)
        after_many_keys    = [math]::Round($afterKeys / 1MB, 2)
        list_replies       = $listOk
        list_refused       = $listErr
        list_first_error   = $listFirstError
        list_transport     = $r1.error
        big_value_ok       = $bigOk
        big_value_err      = $bigErr
        big_value_error    = $bigFirstError
        big_transport      = $r2.error
        distinct_keys_ok   = $keysOk
        keys_transport     = $r3.error
    } | Format-List | Out-String -Width 200
}
finally {
    if (-not $proc.HasExited) { $proc.Kill(); $proc.WaitForExit() }
    Remove-Item "$db*" -ErrorAction SilentlyContinue
}
