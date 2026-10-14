rule Generic_Linux_Infostealer {
    meta:
        description = "Detects generic Linux ELF binaries targeting browser data and SSH keys"
        author = "Threat Research"
        severity = "High"

    strings:
        // ELF Magic Number
        $elf = { 7F 45 4C 46 }
        
        // Browser targets
        $b1 = "/.config/google-chrome" ascii
        $b2 = "/.mozilla/firefox" ascii
        $b3 = "Login Data" ascii
        $b4 = "Cookies" ascii
        
        // System and access keys
        $k1 = "/.ssh/id_" ascii
        $k2 = "/.aws/credentials" ascii
        
        // Profiling markers
        $p1 = "uname -a" ascii
        $p2 = "whoami" ascii

    condition:
        $elf at 0 and (2 of ($b*)) and (1 of ($k*)) and (1 of ($p*))
}
