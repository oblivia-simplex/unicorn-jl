module UcConst



@enum ARCH begin
    ARM   = 0x1
    ARM64 = 0x2
    MIPS  = 0x3
    X86   = 0x4
    PPC   = 0x5
    SPARC = 0x6
    M68K  = 0x7
    MAX   = 0x8
end

@enum MODE begin
    LITTLE_ENDIAN = 0x0000_0000 # Also ARM
    BIG_ENDIAN    = 0x4000_0000

    THUMB   = 0x0000_0010 # Also MICRO
    MCLASS  = 0x0000_0020
    V8      = 0x0000_0040
    ARM926  = 0x0000_0080
    ARM946  = 0x0000_0100
    ARM1176 = 0x0000_0200
end

# TODO: add the rest
end
