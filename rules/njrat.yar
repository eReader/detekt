rule Njrat
{
    meta:
        detection = "Njrat"
        description = "Njrat is a common off-the-shelf trojan which has recently gained popularity in the Middle-East."

    strings:
        $string1 = /(F)romBase64String/
        $string2 = /(B)ase64String/
        $string3 = /(C)onnected/ wide ascii
        $string4 = /(R)eceive/
        $string5 = /(S)end/ wide ascii
        $string6 = /(D)ownloadData/ wide ascii
        $string7 = /(D)eleteSubKey/ wide ascii
        $string8 = /(g)et_MachineName/
        $string9 = /(g)et_UserName/
        $string10 = /(g)et_LastWriteTime/
        $string11 = /(G)etVolumeInformation/
        $string12 = /(O)SFullName/ wide ascii
        $string13 = /(n)etsh firewall/ wide
        $string14 = /(c)md\.exe \/k ping 0 & del/ wide
        $string15 = /(c)md\.exe \/c ping 127\.0\.0\.1 & del/ wide
        $string16 = /(c)md\.exe \/c ping 0 -n 2 & del/ wide
        $string17 = {7C 00 27 00 7C 00 27 00 7C}

    condition:
        10 of them
}