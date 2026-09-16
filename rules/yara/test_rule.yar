rule Dvinesoul_Test
{
    meta:
        description = "Test rule for Dvinesoul Security YARA integration"
        author = "Dvinesoul Security"

    strings:
        $marker = "DVINESOUL_SECURITY_TEST"

    condition:
        $marker
}
