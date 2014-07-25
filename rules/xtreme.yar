rule Xtreme_Strings
{
    strings:
        $1 = /(X)tremeKeylogger/ wide ascii
        $2 = /(X)tremeRAT/ wide ascii
        $3 = /(X)TREMEUPDATE/ wide ascii
        $4 = /(S)TUBXTREMEINJECTED/ wide ascii

    condition:
        any of them
}

rule Xtreme_Units
{
    strings:
        $1 = /(U)nitConfigs/ wide ascii
        $2 = /(U)nitGetServer/ wide ascii
        $3 = /(U)nitKeylogger/ wide ascii
        $4 = /(U)nitCryptString/ wide ascii
        $5 = /(U)nitInstallServer/ wide ascii
        $6 = /(U)nitInjectServer/ wide ascii
        $7 = /(U)nitBinder/ wide ascii
        $8 = /(U)nitInjectProcess/ wide ascii

    condition:
        3 of them
}

