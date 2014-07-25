rule BlackShades_Mods
{
    strings:
        $1 = /(m)odAPI/
        $2 = /(m)odAudio/
        $3 = /(m)odBtKiller/
        $4 = /(m)odCrypt/
        $5 = /(m)odFuctions/
        $6 = /(m)odHijack/
        $7 = /(m)odICallBack/
        $8 = /(m)odIInet/
        $9 = /(m)odInfect/
        $10 = /(m)odInjPE/
        $11 = /(m)odLaunchWeb/
        $12 = /(m)odOS/
        $13 = /(m)odPWs/
        $14 = /(m)odRegistry/
        $15 = /(m)odScreencap/
        $16 = /(m)odSniff/
        $17 = /(m)odSocketMaster/
        $18 = /(m)odSpread/
        $19 = /(m)odSqueezer/
        $20 = /(m)odSS/
        $21 = /(m)odTorrentSeed/

    condition:    
        10 of them
}

rule BlackShades_Tmr
{
    strings:
        $1 = /(t)mrAlarms/
        $2 = /(t)mrAlive/
        $3 = /(t)mrAnslut/
        $4 = /(t)mrAudio/
        $5 = /(t)mrBlink/
        $6 = /(t)mrCheck/
        $7 = /(t)mrCountdown/
        $8 = /(t)mrCrazy/
        $9 = /(t)mrDOS/
        $10 = /(t)mrDoWork/
        $11 = /(t)mrFocus/
        $12 = /(t)mrGrabber/
        $13 = /(t)mrInaktivitet/
        $14 = /(t)mrInfoTO/
        $15 = /(t)mrIntervalUpdate/
        $16 = /(t)mrLiveLogger/
        $17 = /(t)mrPersistant/
        $18 = /(t)mrScreenshot/
        $19 = /(t)mrSpara/
        $20 = /(t)mrSprid/
        $21 = /(t)mrTCP/
        $22 = /(t)mrUDP/
        $23 = /(t)mrWebHide/

    condition:
        10 of them
}
