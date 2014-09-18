rule ShadowTech
{
    meta:
        detection = "ShadowTech RAT"

    strings:
        $string1 = /\#(S)trings/
        $string2 = /\#(G)UID/
        $string3 = /\#(B)lob/
        $string4 = /(S)hadowTech Rat\.exe/
        $string5 = /(S)hadowTech_Rat/

    condition:
        all of them
}
