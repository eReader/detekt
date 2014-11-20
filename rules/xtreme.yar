rule Xtreme
{
    meta:
        detection = "Xtreme RAT"

    strings:
        $string1 = /(X)tremeKeylogger/ wide ascii
        $string2 = /(X)tremeRAT/ wide ascii
        $string3 = /(X)TREMEUPDATE/ wide ascii
        $string4 = /(S)TUBXTREMEINJECTED/ wide ascii

        $unit1 = /(U)nitConfigs/ wide ascii
        $unit2 = /(U)nitGetServer/ wide ascii
        $unit3 = /(U)nitKeylogger/ wide ascii
        $unit4 = /(U)nitCryptString/ wide ascii
        $unit5 = /(U)nitInstallServer/ wide ascii
        $unit6 = /(U)nitInjectServer/ wide ascii
        $unit7 = /(U)nitBinder/ wide ascii
        $unit8 = /(U)nitInjectProcess/ wide ascii

    condition:
        5 of them
}
