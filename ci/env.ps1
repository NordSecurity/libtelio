$scriptDir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
Invoke-Expression ($(python $scriptDir/env.py) -join "`n")
