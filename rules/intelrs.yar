rule IntelRS
{
    meta:
        detection = "IntelRS Stealer"
        description = "This is a spyware of Iranian origin largely used against human rights workers, journalists and political figures involved in the Iranian diaspora. This malware will record everything you type and constantly record screenshots."

    strings:
        $stealer1 = /Stealer\.Annotations/ wide ascii
        $stealer2 = /Stealer\.Browser/ wide ascii
        $stealer3 = /Stealer\.Common/ wide ascii
        $stealer4 = /Stealer\.Communicator/ wide ascii
        $stealer5 = /Stealer\.Compression/ wide ascii
        $stealer6 = /Stealer\.ConfigManager/ wide ascii
        $stealer7 = /Stealer\.Cryptography/ wide ascii
        $stealer8 = /Stealer\.KeyLogger/ wide ascii
        $stealer9 = /Stealer\.Messenger/ wide ascii
        $stealer10 = /Stealer\.Model/ wide ascii
        $stealer11 = /Stealer\.Properties/ wide ascii
        $stealer12 = /Stealer\.SQLite/ wide ascii
        $stealer13 = /Stealer\.SystemInfo/ wide ascii
        $stealer14 = /Stealer\.Update/ wide ascii

    condition:
        7 of them
}
