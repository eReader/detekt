rule Njrat
{
    meta:
        detection = "Njrat"
        description = "Njrat is a common off-the-shelf trojan which has recently gained popularity in the Middle-East."

    strings:
        $a = /#Strings/
        $b = /#GUID/
        $c = /#Blob/

    condition:
        all of them
}
