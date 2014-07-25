rule DarkComet_BOT
{
    strings:
        $1 = "#BOT#OpenUrl" wide ascii
        $2 = "#BOT#Ping" wide ascii
        $3 = "#BOT#RunPrompt" wide ascii
        $4 = "#BOT#SvrUninstall" wide ascii
        $5 = "#BOT#URLDownload" wide ascii
        $6 = "#BOT#URLUpdate" wide ascii
        $7 = "#BOT#VisitUrl" wide ascii
        $8 = "#BOT#CloseServer" wide ascii

    condition:
        all of them
}

rule DarkComet_DDOS
{
    strings:
        $1 = "DDOSHTTPFLOOD" wide ascii
        $2 = "DDOSSYNFLOOD" wide ascii
        $3 = "DDOSUDPFLOOD" wide ascii

    condition:
        all of them
}

rule DarkComet_Keylogger
{
    strings:
        $1 = "ActiveOnlineKeylogger" wide ascii
        $2 = "UnActiveOnlineKeylogger" wide ascii
        $3 = "ActiveOfflineKeylogger" wide ascii
        $4 = "UnActiveOfflineKeylogger" wide ascii

    condition:
        all of them
}

rule DarkComet_RemoteShell
{
    strings:
        $1 = "ACTIVEREMOTESHELL" wide ascii
        $2 = "SUBMREMOTESHELL" wide ascii
        $3 = "KILLREMOTESHELL" wide ascii

    condition:
        all of them
}
