rule Xtreme_Strings
{
    strings:
        $1 = "XtremeKeylogger" wide ascii
        $2 = "XtremeRAT" wide ascii
        $3 = "XTREMEUPDATE" wide ascii
        $4 = "STUBXTREMEINJECTED" wide ascii

    condition:
        any of them
}

rule Xtreme_Units
{
    strings:
        $1 = "UnitConfigs" wide ascii
        $2 = "UnitGetServer" wide ascii
        $3 = "UnitKeylogger" wide ascii
        $4 = "UnitCryptString" wide ascii
        $5 = "UnitInstallServer" wide ascii
        $6 = "UnitInjectServer" wide ascii
        $7 = "UnitBinder" wide ascii
        $8 = "UnitInjectProcess" wide ascii

    condition:
        3 of them
}

