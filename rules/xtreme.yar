rule Xtreme
{
    meta:
        detection = "Xtreme RAT"
        description = "This is a common trojan which is free to download from the Internet and available to just about anyone. It should be normally detected and quarantined by major AntiVirus software. Although it is impossible to guess who might be targeting you, you should seek for assistance nevertheless."

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
        any of ($string*) or 3 of ($unit*)
}
