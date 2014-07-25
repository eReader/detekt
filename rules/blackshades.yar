rule BlackShades_Mods
{
    strings:
        $1 = "modAPI"
        $2 = "modAudio"
        $3 = "modBtKiller"
        $4 = "modCrypt"
        $5 = "modFuctions"
        $6 = "modHijack"
        $7 = "modICallBack"
        $8 = "modIInet"
        $9 = "modInfect"
        $10 = "modInjPE"
        $11 = "modLaunchWeb"
        $12 = "modOS"
        $13 = "modPWs"
        $14 = "modRegistry"
        $15 = "modScreencap"
        $16 = "modSniff"
        $17 = "modSocketMaster"
        $18 = "modSpread"
        $19 = "modSqueezer"
        $20 = "modSS"
        $21 = "modTorrentSeed"

    condition:    
        10 of them
}

rule BlackShades_Tmr
{
    strings:
        $1 = "tmrAlarms"
        $2 = "tmrAlive"
        $3 = "tmrAnslut"
        $4 = "tmrAudio"
        $5 = "tmrBlink"
        $6 = "tmrCheck"
        $7 = "tmrCountdown"
        $8 = "tmrCrazy"
        $9 = "tmrDOS"
        $10 = "tmrDoWork"
        $11 = "tmrFocus"
        $12 = "tmrGrabber"
        $13 = "tmrInaktivitet"
        $14 = "tmrInfoTO"
        $15 = "tmrIntervalUpdate"
        $16 = "tmrLiveLogger"
        $17 = "tmrPersistant"
        $18 = "tmrScreenshot"
        $19 = "tmrSpara"
        $20 = "tmrSprid"
        $21 = "tmrTCP"
        $22 = "tmrUDP"
        $23 = "tmrWebHide"

    condition:
        10 of them
}
