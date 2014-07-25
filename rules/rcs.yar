rule RCSScout_Format
{
    strings:
        $1 = "%02X%02X%02X%02X%c%c"
        $2 = "%c%c%c%02X%02X%02X%02X"

    condition:
        all of them
}

rule RCSScout_Engine
{
    strings:
        $1 = "Engine started" wide ascii
        $2 = "Running in background" wide ascii
        $3 = "Locking doors" wide ascii
        $4 = "Rotors engaged" wide ascii
        $5 = "I'm going to start it" wide ascii

    condition:
        2 of them
}

rule RCSScout_Start
{
    strings:
        $1 = "Starting upgrade!" wide ascii
        $2 = "I'm going to start the program" wide ascii
        $3 = "is it ok?" wide ascii
        $4 = "Click to start the program" wide ascii

    condition:
        2 of them
}

rule RCSScout_Upd
{
    strings:
        $1 = "UpdJob" wide ascii
        $2 = "UpdTimer" wide ascii

    condition:
        all of them
}

rule RCS_Debug
{
    strings:
        $1 = "- Checking components" wide ascii
        $2 = "- Activating hiding system" wide ascii
        $3 = "fully operational" wide ascii

    condition:
        2 of them
}

rule RCS_Log
{
    strings:
        $1 = "- Browser activity (FF)" wide ascii
        $2 = "- Browser activity (IE)" wide ascii
        $3 = "- About to call init routine at %p" wide ascii
        $4 = "- Calling init routine at %p" wide ascii

    condition:
        2 of them
}

rule RCS_Errors
{
    strings:
        $1 = "[Unable to deploy]" wide ascii
        $2 = "[The system is already monitored]" wide ascii

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
        $1 = "Unhackme.exe"
        $2 = "hackmon.exe"
        $3 = "hiddenfinder.exe"
        $4 = "rootkitbuster*.exe"
        $5 = "RootkitRevealer.exe"
        $6 = "avgarkt.exe"
        $7 = "avgscanx.exe"
        $8 = "avk.exe"
        $9 = "avp.exe"
        $10 = "avscan.exe"
        $11 = "bb_in.exe"
        $12 = "bgscan.exe"
        $13 = "IceSword.exe"
        $14 = "k7*.exe"

    condition:
        all of them
}

rule RCS_StealCreds
{
    strings:
        $1 = "SELECT * FROM cookies;"
        $2 = "SELECT * FROM moz_cookies;"
        $3 = "SELECT * FROM logins;"

    condition:
        all of them
}

rule RCS_Skype
{
    strings:
        $1 = "SkypeControlAPIAttach"
        $2 = "SkypeControlAPIDiscover"
        $3 = "skype.exe"
        $4 = "skypepm.exe"
        $5 = "Skype.exe /nosplash /minimized"

    condition:
        all of them
}
