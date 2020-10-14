using Test

println("hello")

using Unicorn: Machine, Emulator, Perm, reg_write, reg_read, mem_map, mem_write, emu_start, X86

function test_eflags()::Bool

    # 0:    4d 31 f6                 xor    r14, r14
    # 3:    45 85 f6                 test   r14d, r14d
    # 6:    75 fe                    jne    0x6
    # 8:    f4                       hlt

    code::Vector{UInt8} = [0x48, 0x31, 0xf6, 0x45, 0x85, 0xf6, 0x75, 0xfe, 0xf4]

    emu = Emulator(Machine.X86, Machine.MODE_64)
    reg_write(emu, X86.RegId.RIP, Int(0x0000_0000_0060_00b0))
    reg_write(emu, X86.RegId.EFLAGS, Int(0x0000_0000_0000_0246))

    mem_map(emu, address = 0x0000_0000_0060_0000, size = 0x0000_0000_0000_1000)
    mem_write(emu, address = UInt64(0x60_00b0), bytes = code)

    emu_start(
        emu,
        begin_addr = UInt64(0x60_00b0 + 0x6),
        until_addr = UInt64(0),
        inst_count = UInt64(1),
    )

    result = reg_read(emu, X86.RegId.RIP)
    return result == 0x6000b0 + 8
end



@testset "Test x86_64 conditional execution" begin
    @test test_eflags()  
end
