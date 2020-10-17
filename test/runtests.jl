using Test

using Unicorn

function test_execution()

    # 0:    4d 31 f6                 xor    r14, r14
    # 3:    45 85 f6                 test   r14d, r14d
    # 6:    75 fe                    jne    0x6
    # 8:    f4                       hlt

    code::Vector{UInt8} = [0x48, 0x31, 0xf6, 0x45, 0x85, 0xf6, 0x75, 0xfe, 0xf4]

    emu = Emulator(Arch.X86, Mode.MODE_64)
    reg_write(emu, register = X86.Register.RIP, value = Int(0x0000_0000_0060_00b0))
    @test reg_read(emu, X86.Register.RIP) == 0x0000_0000_0060_00b0
    reg_write(emu, register = X86.Register.EFLAGS, value = Int(0x0000_0000_0000_0246))
    @test reg_read(emu, X86.Register.EFLAGS) == 0x0000_0000_0000_0246

    mem_map(emu, address = 0x0000_0000_0060_0000, size = 0x0000_0000_0000_1000)
    mem_write(emu, address = UInt64(0x60_00b0), bytes = code)

    # Test to ensure that we can read those bytes back
    code_read = mem_read(emu, address = UInt64(0x60_00b0), size = length(code))
    @test code_read == code

    # Test code hooks
    addrs = []
    ran_the_callback = false
    function callback(engine::UcHandle, addr::UInt64, size::UInt32)::Nothing
        push!(addrs, addr)
        ran_the_callback = true
        return
    end
    code_hook_add(emu, callback = callback)

    emu_start(
        emu,
        begin_addr = UInt64(0x60_00b0 + 0x6),
        until_addr = UInt64(0),
        steps = UInt64(1),
    )

    result = reg_read(emu, X86.Register.RIP)
    @test result == 0x60_00b0 + 8

    # Check the data written to by the code hook callback
    @test ran_the_callback
    @test addrs == [0x60_00b6, 0x60_00b8]

    @test length(emu.hooks) == 1
    delete_all_hooks(emu)
    @test length(emu.hooks) == 0
end


struct MemoryEvent
    ip_addr::UInt64
    address::UInt64
    access_type::MemoryAccess.t
    data::Vector{UInt8}
end

function test_mem_hook()

    # nop
    # nop
    # mov 0x8(%rsp), %rdi // memory read
    # nop
    # nop
    code = [0x90, 0x90, 0x48, 0x8b, 0x7c, 0x24, 0x08, 0x90, 0x90]

    emu = Emulator(Arch.X86, Mode.MODE_64)

    mem_map(emu, address = 0, size = 0x1000)
    mem_write(emu, address = 0, bytes = code)

    reg_write(emu, register = X86.Register.RSP, value = 0x100)

    events = []

    function callback(
        engine::UcHandle,
        type::MemoryAccess.t,
        address::UInt64,
        size::Cint,
        data::Int64,
    )
        ip_addr = reg_read(engine, X86.Register.RIP)
        bytes = mem_read(engine, address, size)
        event = MemoryEvent(ip_addr, address, type, bytes)
        @show event
        push!(events, event)
        return nothing
    end

    mem_hook_add(emu, access_type = HookType.MEM_READ | HookType.MEM_WRITE, callback = callback)

    emu_start(emu, begin_addr = 0, until_addr = 0x100, steps = 5)

    @show events

    @test events[1].access_type == MemoryAccess.READ
    @test events[1].address == 0x100 + 8
    @test events[1].ip_addr == 2
    @test events[1].data == fill(0, 8)

    delete_all_hooks(emu)

    finalize(emu)
end

function test_mem_regions()

    emu = Emulator(Arch.ARM, Mode.THUMB)

    params = [
        (0x40_000, 0x8000, Perm.READ),
        (0x1000, 0x1000, Perm.READ | Perm.WRITE),
        (0x8000, 0x2000, Perm.ALL),
    ]

    for (address, size, perms) in params
        mem_map(emu, address = address, size = size, perms = perms)
    end

    regions = mem_regions(emu)

    for (p, r) in zip(params, regions)
        @test r.from == p[1] && r.to == p[1] + p[2] - 1 && r.perms == p[3]
    end

end

@testset "Test x86_64 conditional execution" begin
    test_execution()
    test_mem_hook()
    test_mem_regions()
end
