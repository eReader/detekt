rule Njrat
{
    meta:
        detection = "Njrat"
        description = "Njrat is a common off-the-shelf trojan which has recently gained popularity in the Middle-East."

    strings:
        $get1 = /(g)et_Application/
        $get2 = /(g)et_Assembly/
        $get3 = /(g)et_Available/
        $get4 = /(g)et_Capacity/
        $get5 = /(g)et_Client/
        $get6 = /(g)et_Computer/
        $get7 = /(g)et_Connected/
        $get8 = /(g)et_Culture/
        $get9 = /(g)et_Default/
        $get10 = /(g)et_ExecutablePath/
        $get11 = /(g)et_Forms/
        $get12 = /(g)et_FullName/
        $get13 = /(g)et_GetInstance/
        $get14 = /(g)et_Info/
        $get15 = /(g)et_InnerException/
        $get16 = /(g)et_IsDisposed/
        $get17 = /(g)et_Length/
        $get18 = /(g)et_MachineName/
        $get19 = /(g)et_MainWindowTitle/
        $get20 = /(g)et_Message/
        $get21 = /(g)et_Network/
        $get22 = /(g)et_OSFullName/
        $get23 = /(g)et_OSVersion/
        $get24 = /(g)et_ResourceManager/
        $get25 = /(g)et_ServicePack/
        $get26 = /(g)et_Settings/
        $get27 = /(g)et_User/
        $get28 = /(g)et_UserName/
        $get29 = /(g)et_WebServices/

    condition:
        10 of them
}
