
rule test_rule
{
    meta:
        author = Saurit Mondal
        date = 
        description = Test rule
    strings:
        $string1 = "Hello world"
    condition:
        any of them

}