rule DarkComet
{
    meta:
        detection = "DarkComet RAT"
        description = "This is a common trojan which is free to download from the Internet and available to just about anyone. It should be normally detected and quarantined by major AntiVirus software. Although it is impossible to guess who might be targeting you, you should seek for assistance nevertheless."

    strings:
        $filter1 = "detekt" nocase
        $filter2 = "rule DarkComet"
        $filter3 = "$bot1"
        $filter4 = "$ddos1"
        $filter5 = "$keylogger1"
        $filter6 = "$shell1"

        $bot1 = /(#)BOT#OpenUrl/ wide ascii
        $bot2 = /(#)BOT#Ping/ wide ascii
        $bot3 = /(#)BOT#RunPrompt/ wide ascii
        $bot4 = /(#)BOT#SvrUninstall/ wide ascii
        $bot5 = /(#)BOT#URLDownload/ wide ascii
        $bot6 = /(#)BOT#URLUpdate/ wide ascii
        $bot7 = /(#)BOT#VisitUrl/ wide ascii
        $bot8 = /(#)BOT#CloseServer/ wide ascii

        $ddos1 = /(D)DOSHTTPFLOOD/ wide ascii
        $ddos2 = /(D)DOSSYNFLOOD/ wide ascii
        $ddos3 = /(D)DOSUDPFLOOD/ wide ascii

        $keylogger1 = /(A)ctiveOnlineKeylogger/ wide ascii
        $keylogger2 = /(U)nActiveOnlineKeylogger/ wide ascii
        $keylogger3 = /(A)ctiveOfflineKeylogger/ wide ascii
        $keylogger4 = /(U)nActiveOfflineKeylogger/ wide ascii

        $shell1 = /(A)CTIVEREMOTESHELL/ wide ascii
        $shell2 = /(S)UBMREMOTESHELL/ wide ascii
        $shell3 = /(K)ILLREMOTESHELL/ wide ascii

    condition:
        (4 of ($bot*) or all of ($ddos*) or all of ($keylogger*) or all of ($shell*)) and not any of ($filter*)
}
