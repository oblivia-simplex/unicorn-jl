module Unicorn

using BitFlags


@bitflag Perm::UInt8 begin
    NONE = 0x0
    READ = 0x1
    WRITE = 0x2
    EXEC = 0x4
end
ALL = READ | WRITE | EXEC

@enum Arch begin
    ARM = 0x1
    ARM64 = 0x2
    MIPS = 0x3
    X86 = 0x4
    PPC = 0x5
    SPARC = 0x6
    M68K = 0x7
    MAX = 0x8
end

# TODO: add the rest of the modes
@enum Mode begin
    LITTLE_ENDIAN = 0x0000_0000 # Also ARM
    BIG_ENDIAN = 0x4000_0000

    # for arm architectures
    THUMB = 0x0000_0010 # Also MICRO
    MCLASS = 0x0000_0020
    V8 = 0x0000_0040
    ARM926 = 0x0000_0080
    ARM946 = 0x0000_0100
    ARM1176 = 0x0000_0200

    # for x86 and x86_64
    MODE_16 = 1 << 1
    MODE_32 = 1 << 2
    MODE_64 = 1 << 3
end


@enum Err begin
    OK = 0
    NOMEM = 1
    ARCH = 2  # Unsupported Architecture
    HANDLE = 3  # Invalid Handle
    MODE = 4  # Invalid or unsupported mode
    VERS = 5  # Unsupported version
    READ_UNMAPPED = 6 # Quit emulation due to READ on unmapped mem
    WRITE_UNMAPPED = 7
    FETCH_UNMAPPED = 8
    HOOK = 9
    INSN_INVALID = 10
    MAP = 11
    WRITE_PROT = 12
    READ_PROT = 13
    FETCH_PROT = 14
    ARG = 15
    READ_UNALIGNED = 16
    WRITE_UNALIGNED = 17
    FETCH_UNALIGNED = 18
    HOOK_EXIST = 19
    RESOURCE = 20
    EXCEPTION = 21
end


struct UcException <: Exception
    code::Err
end

# FIXME hack
UC_PATH = "/home/lucca/src/unicorn/libunicorn.so"

const UcHandle = Ptr{Cvoid}

function uc_free(uc::UcHandle)
    println("Freeing unicorn emulator at $(uc)...")
    eval(:(ccall((:uc_free, $UC_PATH), Nothing, (UcHandle,), $uc)))
end

# The unicorn emulator object
mutable struct Emulator
    arch::Arch
    mode::Mode
    handle::UcHandle

    # Constructor
    Emulator(arch::Arch, mode::Mode) = begin
        println("initializing emulator with $arch, $mode")
        uc = Ref{UcHandle}()
        # bit of a hack to get around some issues with library paths
        err = eval(
            :(ccall(
                (:uc_open, $UC_PATH), # function name, library path
                Err,          # return type
                (UInt, UInt, Ref{UcHandle}),
                $arch,
                $mode,
                $uc,
            )),
        )
        check(err)
        emu = new(arch, mode, uc[])
        finalizer(e -> uc_free(e.handle), emu)
        return emu
    end
end

function check(result::Err)
    if result != OK
        throw(UcException(result))
    end
end

# Map memory in for emulation.
# This API adds a memory region that can be used by emulation.
#
# @uc: handle returned by uc_open()
# @address: starting address of the new memory region to be mapped in.
#    This address must be aligned to 4KB, or this will return with UC_ERR_ARG error.
# @size: size of the new memory region to be mapped in.
#    This size must be multiple of 4KB, or this will return with UC_ERR_ARG error.
# @perms: Permissions for the newly mapped region.
#    This must be some combination of UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
#    or this will return with UC_ERR_ARG error.
#
# @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
#   for detailed error).
#
function mem_map(emu::Emulator, address::UInt, size::UInt, perms::Perm)
    address = UInt64(address)
    size = UInt64(size)
    check(eval(
        :(ccall(
            (:uc_mem_map, $UC_PATH),
            Err,
            (UcHandle, UInt64, UInt, UInt32),
            $(emu.handle),
            $address,
            $size,
            $perms,
        )),
    ))
end

# Emulate machine code in a specific duration of time.
#
# @emu: handle returned by uc_open()
# @begin_addr: address where emulation starts
# @until_addr: address where emulation stops (i.e when this address is hit)
# @μs_timeout: duration to emulate the code (in microseconds). When this value is 0,
#        we will emulate the code in infinite time, until the code is finished.
# @inst_count: the number of instructions to be emulated. When this value is 0,
#        we will emulate all the code available, until the code is finished.
#
# @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
#   for detailed error).
function emu_start(
    emu::Emulator,
    begin_addr::Int,
    until_addr::Int,
    μs_timeout::Int,
    inst_count::Int,
)::Err
    eval(
        :(ccall(
            (:uc_mem_map, $UC_PATH),
            Err,
            (UcHandle, UInt64, UInt64, UInt64, UInt),
            $(emu.handle),
            $begin_addr,
            $until_addr,
            $μs_timeout,
            $inst_count,
        )),
    )
end

function emu_start(emu::Emulator, begin_addr::Int)
    emu_start(emu, begin_addr, 0, 0, 0)
end


function mem_write(emu::Emulator, address::UInt64, bytes::Vector{UInt8})::UInt
    size = length(bytes)
    ptr = pointer(bytes)
    err = eval(
        :(ccall(
            (:uc_mem_write, $UC_PATH),
            Err,
            (UcHandle, UInt64, (Ptr{UInt8}), UInt),
            $(emu.handle),
            $address,
            $ptr,
            $size,
        )),
    )
    check(err)
    size
end


greet() = println("Welcome to the Unicorn module.")

end
