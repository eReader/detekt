rule ShadowTech
{
    meta:
        detection = "ShadowTech RAT"
        description = "ShawdowTech is a common RAT which is available for download for free on the Internet. It has been observed for example used in Syria against prominent figures of the opposition."

    strings:
        $string1 = /\#(S)trings/
        $string2 = /\#(G)UID/
        $string3 = /\#(B)lob/
        $string4 = /(S)hadowTech Rat\.exe/
        $string5 = /(S)hadowTech_Rat/

    condition:
        all of them
}
