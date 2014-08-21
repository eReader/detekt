rule njRAT
{
    meta:
        detection = "njRAT"
        description = "njRAT is a common off-the-shelf trojan which has recently gained popularity in the Middle-East."

    strings:
        $get1 = "get_Application"
        $get2 = "get_Assembly"
        $get3 = "get_Available"
        $get4 = "get_Capacity"
        $get5 = "get_Client"
        $get6 = "get_Computer"
        $get7 = "get_Connected"
        $get8 = "get_Culture"
        $get9 = "get_Default"
        $get10 = "get_ExecutablePath"
        $get11 = "get_Forms"
        $get12 = "get_FullName"
        $get13 = "get_GetInstance"
        $get14 = "get_Info"
        $get15 = "get_InnerException"
        $get16 = "get_IsDisposed"
        $get17 = "get_Length"
        $get18 = "get_MachineName"
        $get19 = "get_MainWindowTitle"
        $get20 = "get_Message"
        $get21 = "get_Network"
        $get22 = "get_OSFullName"
        $get23 = "get_OSVersion"
        $get24 = "get_ResourceManager"
        $get25 = "get_ServicePack"
        $get26 = "get_Settings"
        $get27 = "get_User"
        $get28 = "get_UserName"
        $get29 = "get_WebServices"

    condition:
        10 of them
}
