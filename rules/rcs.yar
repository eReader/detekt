rule RCSScout_Format
{
    strings:
        $1 = /(%)02X%02X%02X%02X%c%c/
        $2 = /(%)c%c%c%02X%02X%02X%02X/

    condition:
        all of them
}

rule RCSScout_Engine
{
    strings:
        $1 = /(E)ngine started/ wide ascii
        $2 = /(R)unning in background/ wide ascii
        $3 = /(L)ocking doors/ wide ascii
        $4 = /(R)otors engaged/ wide ascii
        $5 = /(I)\'m going to start it/ wide ascii

    condition:
        2 of them
}

rule RCSScout_Start
{
    strings:
        $1 = /Starting upgrade\!/ wide ascii
        $2 = /(I)\'m going to start the program/ wide ascii
        $3 = /(i)s it ok\?/ wide ascii
        $4 = /(C)lick to start the program/ wide ascii

    condition:
        2 of them
}

rule RCSScout_Upd
{
    strings:
        $1 = /(U)pdJob/ wide ascii
        $2 = /(U)pdTimer/ wide ascii

    condition:
        all of them
}

rule RCS_Debug
{
    strings:
        $1 = /\- Checking components/ wide ascii
        $2 = /\- Activating hiding system/ wide ascii
        $3 = /(f)ully operational/ wide ascii

    condition:
        2 of them
}

rule RCS_Log
{
    strings:
        $1 = /\- Browser activity \(FF\)/ wide ascii
        $2 = /\- Browser activity \(IE\)/ wide ascii
        $3 = /\- About to call init routine at %p/ wide ascii
        $4 = /\- Calling init routine at %p/ wide ascii

    condition:
        2 of them
}

rule RCS_Errors
{
    strings:
        $1 = /\[Unable to deploy\]/ wide ascii
        $2 = /\[The system is already monitored\]/ wide ascii

    condition:
        all of them
}

rule RCS_Config
{
    strings:
        $1 = /\<NAME\>HACKSTOP v1\.00\<\/NAME\>/
        $2 = /\<NAME\>HACKSTOP v1\.10, v1.11\<\/NAME\>/
        $3 = /\<NAME\>HACKSTOP v1\.10p1\<\/NAME\>/
        $4 = /\<NAME\>HACKSTOP v1\.11c\<\/NAME\>/
        $5 = /\<NAME\>HACKSTOP v1\.13\<\/NAME\>/
        $6 = /\<NAME\>HACKSTOP v1\.13 \/ DarkStop v1.0\<\/NAME\>/
        $7 = /\<NAME\>HACKSTOP v1\.17\<\/NAME\>/
        $8 = /\<NAME\>HACKSTOP v1\.18\<\/NAME\>/
        $9 = /\<NAME\>HACKSTOP v1\.19\<\/NAME\>/
        $10 = /\<NAME\>Cracked by AutoHack \(1\)\<\/NAME\>/
        $11 = /\<NAME\>Cracked by Autohack \(2\)\<\/NAME\>/
        $12 = /\<NAME\>modified HACKSTOP v1\.11f\<\/NAME\>/
        $13 = /\<NAME\>WARNING \-\&gt; TROJAN \-\&gt; ADinjector\<\/NAME\>/

    condition:
        all of them
}

rule RCS_Processes
{
    strings:
        $1 = /(U)nhackme\.exe/
        $2 = /(h)ackmon\.exe/
        $3 = /(h)iddenfinder\.exe/
        $4 = /(r)ootkitbuster\*\.exe/
        $5 = /(R)ootkitRevealer\.exe/
        $6 = /(a)vgarkt\.exe/
        $7 = /(a)vgscanx\.exe/
        $8 = /(a)vk\.exe/
        $9 = /(a)vp\.exe/
        $10 = /(a)vscan\.exe/
        $11 = /(b)b_in\.exe/
        $12 = /(b)gscan\.exe/
        $13 = /(I)ceSword\.exe/
        $14 = /(k)7\*\.exe/

    condition:
        all of them
}

rule RCS_StealCreds
{
    strings:
        $1 = /SELECT \* FROM cookies;/
        $2 = /SELECT \* FROM moz_cookies;/
        $3 = /SELECT \* FROM logins;/

    condition:
        all of them
}

rule RCS_Skype
{
    strings:
        $1 = /(S)kypeControlAPIAttach/
        $2 = /(S)kypeControlAPIDiscover/
        $3 = /(s)kype\.exe/
        $4 = /(s)kypepm\.exe/
        $5 = /(S)kype\.exe \/nosplash \/minimized/

    condition:
        all of them
}
