rule DarkComet_BOT
{
    strings:
        $1 = /(#)BOT#OpenUrl/ wide ascii
        $2 = /(#)BOT#Ping/ wide ascii
        $3 = /(#)BOT#RunPrompt/ wide ascii
        $4 = /(#)BOT#SvrUninstall/ wide ascii
        $5 = /(#)BOT#URLDownload/ wide ascii
        $6 = /(#)BOT#URLUpdate/ wide ascii
        $7 = /(#)BOT#VisitUrl/ wide ascii
        $8 = /(#)BOT#CloseServer/ wide ascii

    condition:
        all of them
}

rule DarkComet_DDOS
{
    strings:
        $1 = /(D)DOSHTTPFLOOD/ wide ascii
        $2 = /(D)DOSSYNFLOOD/ wide ascii
        $3 = /(D)DOSUDPFLOOD/ wide ascii

    condition:
        all of them
}

rule DarkComet_Keylogger
{
    strings:
        $1 = /(A)ctiveOnlineKeylogger/ wide ascii
        $2 = /(U)nActiveOnlineKeylogger/ wide ascii
        $3 = /(A)ctiveOfflineKeylogger/ wide ascii
        $4 = /(U)nActiveOfflineKeylogger/ wide ascii

    condition:
        all of them
}
