rule FinSpy_PasswordSteal
{
    strings:
        $1 = /\/scomma kbd101\.sys/ wide ascii
        $2 = /(N)AME,EMAIL CLIENT,EMAIL ADDRESS,SERVER NAME,SERVER TYPE,USERNAME,PASSWORD,PROFILE/ wide ascii
        $3 = /\/scomma excel2010\.part/ wide ascii
        $4 = /(A)PPLICATION,PROTOCOL,USERNAME,PASSWORD/ wide ascii
        $5 = /\/stab MSVCR32\.manifest/ wide ascii
        $6 = /\/scomma MSN2010\.dll/ wide ascii
        $7 = /\/scomma Firefox\.base/ wide ascii
        $8 = /(I)NDEX,URL,USERNAME,PASSWORD,USERNAME FIELD,PASSWORD FIELD,FILE,HTTP/ wide ascii
        $9 = /\/scomma IE7setup\.sys/ wide ascii
        $10 = /(O)RIGIN URL,ACTION URL,USERNAME FIELD,PASSWORD FIELD,USERNAME,PASSWORD,TIMESTAMP/ wide ascii
        $11 = /\/scomma office2007\.cab/ wide ascii
        $12 = /(U)RL,PASSWORD TYPE,USERNAME,PASSWORD,USERNAME FIELD,PASSWORD FIELD/ wide ascii
        $13 = /\/scomma outlook2007\.dll/ wide ascii
        $14 = /(F)ILENAME,ENCRYPTION,VERSION,CRC,PASSWORD 1,PASSWORD 2,PASSWORD 3,PATH,SIZE,LAST MODIFICATION DATE,ERROR/ wide ascii

    condition:
        any of them
}

rule FinSpy_ScreenRecorder
{
    strings:
        $1 = /(s)111o00000000\.dat/ wide ascii
        $2 = /(t)111o00000000\.dat/ wide ascii
        $3 = /(f)113o00000000\.dat/ wide ascii
        $4 = /(w)114o00000000\.dat/ wide ascii
        $5 = /(u)112Q00000000\.dat/ wide ascii
        $6 = /(v)112Q00000000\.dat/ wide ascii
        $7 = /(v)112O00000000\.dat/ wide ascii

    condition:
        any of them
}

rule FinSpy_KeyLogger
{
    strings:
        $1 = /\<%s UTC %s\|%d\|%s\>/ wide ascii
        $2 = /1201[0-9A-F]{8}\.dat/ wide ascii

    condition:
        any of them
}

rule FinSpy_MicRecorder
{
    strings:
        $1 = /2101[0-9A-F]{8}\.dat/ wide ascii

    condition:
        $1
}

rule FinSpy_SkypeRecorder
{
    strings:
        $1 = /\[%19s\] %25s\:    %s/ wide ascii
        $2 = /Global\\\{A48F1A32\-A340\-11D0\-BC6B\-00A0C903%\.04X\}/ wide
        $3 = /(1411|1421|1431|1451)[0-9A-F]{8}\.dat/ wide ascii

    condition:
        any of them
}

rule FinSpy_MouseRecorder
{
    strings:
        $1 = /(m)sc183Q000\.dat/ wide ascii
        $2 = /2201[0-9A-F]{8}\.dat/ wide ascii

    condition:
        any of them
}

rule FinSpy_Driver
{
    strings:
        $1 = /\\\\\\\\\.\\\\driverw/ wide ascii

    condition:
        any of them
}

rule FinSpy_Mutexes
{
    strings:
        $1 = /(W)ininetProxyMutex/ wide ascii
        $2 = /(W)ininetProxyExit/ wide ascii
        $3 = /(W)ininetProxyMemory/ wide ascii

    condition:
        any of them
}

rule FinSpy_Typo
{
    strings:
        $1 = /(S)creenShort Recording/ wide ascii

    condition:
        $1
}

rule FinSpy_JaneDow
{
    strings:
        $1 = /(J)ane Dow\'s x32 machine/ wide ascii
        $2 = /(J)ane Dow\'s x64 machine/ wide ascii

    condition:
        any of them
}

rule FinSpy_Versions
{
    strings:
        $1 = /(f)inspyv2/ nocase
        $2 = /(f)inspyv4/ nocase

    condition:
        any of them
}

rule FinSpy_Bootkit
{
    strings:
        $1 = /(b)ootkit_x32driver/
        $2 = /(b)ootkit_x64driver/

    condition:
        any of them
}

rule FinSpy_Encryption
{
    strings:
        $1 = /\\x90\\x03\\xFE\\x00\\xFA\\xF9\\xF8\\xFF/
        $2 = /\\x90\\x03\\xFE\\x00\\xEA\\xE9\\xE8\\xFF/

    condition:
        any of them
}
