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
