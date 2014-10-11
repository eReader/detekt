rule RCS_Scout
{
    meta:
        detection = "Hacking Team RCS Scout"

    strings:
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

        $lookma1 = /(O)wning PCI bus/ wide
        $lookma2 = /(F)ormatting bios/ wide
        $lookma3 = /(P)lease insert a disk in drive A:/ wide
        $lookma4 = /(U)pdating CPU microcode/ wide
        $lookma5 = /(N)ot sure what's happening/ wide
        $lookma6 = /(L)ook ma, no thread id\! \\\\o\// wide        

    condition:
        all of ($engine*) or all of ($start*) or all of ($upd*) or 4 of ($lookma*)
}

rule RCS_Backdoor
{
    meta:
        detection = "Hacking Team RCS Backdoor"

    strings:
        $debug1 = /\- (C)hecking components/ wide ascii
        $debug2 = /\- (A)ctivating hiding system/ wide ascii
        $debug3 = /(f)ully operational/ wide ascii

        $log1 = /\- Browser activity \(FF\)/ wide ascii
        $log2 = /\- Browser activity \(IE\)/ wide ascii
        
        // Cause false positives.
        //$log3 = /\- About to call init routine at %p/ wide ascii
        //$log4 = /\- Calling init routine at %p/ wide ascii

        $error1 = /\[Unable to deploy\]/ wide ascii
        $error2 = /\[The system is already monitored\]/ wide ascii

    condition:
        2 of ($debug*) or 2 of ($log*) or all of ($error*)
}
