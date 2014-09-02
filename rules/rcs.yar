rule RCS_Scout
{
    meta:
        detection = "Hacking Team RCS Scout"
        description = "This is a very sophisticated backdoor produced by an Italian company and sold to government agencies worldwide. You might be targeted by yours or a foreign government. You should be really careful on your next steps in order to not further jeopardize your situation."

    strings:
        $filter1 = "detekt" nocase
        $filter2 = "rule RCS_Scout"
        $filter3 = "$format1"
        $filter4 = "$engine1"
        $filter5 = "$start1"
        $filter6 = "$upd1"

        $format1 = /(%)02X%02X%02X%02X%c%c/
        $format2 = /(%)c%c%c%02X%02X%02X%02X/

        $engine1 = /(E)ngine started/ wide ascii
        $engine2 = /(R)unning in background/ wide ascii
        $engine3 = /(L)ocking doors/ wide ascii
        $engine4 = /(R)otors engaged/ wide ascii
        $engine5 = /(I)\'m going to start it/ wide ascii

        $start1 = /Starting upgrade\!/ wide ascii
        $start2 = /(I)\'m going to start the program/ wide ascii
        $start3 = /(i)s it ok\?/ wide ascii
        $start4 = /(C)lick to start the program/ wide ascii

        $upd1 = /(U)pdJob/ wide ascii
        $upd2 = /(U)pdTimer/ wide ascii

    condition:
        (all of ($format*) or all of ($engine*) or 2 of ($start*) or all of ($upd*)) and not any of ($filter*)
}

rule RCS_Backdoor
{
    meta:
        detection = "Hacking Team RCS Backdoor"
        description = "This is a very sophisticated backdoor produced by an Italian company and sold to government agencies worldwide. You might be targeted by yours or a foreign government. You should be really careful on your next steps in order to not further jeopardize your situation."

    strings:
        $filter1 = "detekt" nocase
        $filter2 = "rule RCS_Backdoor"
        $filter3 = "$debug1"
        $filter4 = "$log1"
        $filter5 = "$error1"

        $debug1 = /\- (C)hecking components/ wide ascii
        $debug2 = /\- (A)ctivating hiding system/ wide ascii
        $debug3 = /(f)ully operational/ wide ascii

        $log1 = /\- Browser activity \(FF\)/ wide ascii
        $log2 = /\- Browser activity \(IE\)/ wide ascii

        // Raise false-positives.
        //$log3 = /\- (A)bout to call init routine at %p/ wide ascii
        //$log4 = /\- (C)alling init routine at %p/ wide ascii

        $error1 = /\[Unable to deploy\]/ wide ascii
        $error2 = /\[The system is already monitored\]/ wide ascii

    condition:
        (2 of ($debug*) or 2 of ($log*) or all of ($error*)) and not any of ($filter*)
}
