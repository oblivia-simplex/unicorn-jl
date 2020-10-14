module Unicorn

import Libdl
using BitFlags

__precompile__(false)


include("./X86.jl")

const Register = Union{X86.RegId.Register,}

@bitflag Perm::UInt32 begin
    NONE = 0x0
    READ = 0x1
    WRITE = 0x2
    EXEC = 0x4
end
ALL = READ | WRITE | EXEC

module Machine
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
end

@enum Err begin
    OK = 0
    NOMEM = 1
    ARCH = 2  # Unsupported Machine
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
LIBUNICORN = Libdl.dlopen(UC_PATH)


const UcHandle = Ptr{Cvoid}

function uc_free(uc::UcHandle)
    println("Freeing unicorn emulator at $(uc)...")
    uc_free = Libdl.dlsym(LIBUNICORN, :uc_free)
    ccall(uc_free, Nothing, (UcHandle,), uc)
end

# The unicorn emulator object
mutable struct Emulator
    arch::Machine.Arch
    mode::Machine.Mode
    handle::UcHandle

    # Constructor
    Emulator(arch::Machine.Arch, mode::Machine.Mode) = begin
        uc = Ref{UcHandle}()

        uc_open = Libdl.dlsym(LIBUNICORN, :uc_open)
        check(ccall(uc_open, Err, (UInt, UInt, Ref{UcHandle}), arch, mode, uc))
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
function mem_map(
    handle::UcHandle;
    address::UInt64 = 0x0000_0000_0000_0000,
    size::UInt = 0x0000_0000_0000_1000,
    perms::Perm = ALL,
)
    uc_mem_map = Libdl.dlsym(LIBUNICORN, :uc_mem_map)
    check(ccall(
        uc_mem_map,
        Err,
        (UcHandle, UInt64, UInt, UInt32),
        handle,
        address,
        size,
        perms,
    ))
end

function mem_map(emu::Emulator; address = 0, size = 4096, perms::Perm = ALL)
    mem_map(emu.handle, address = UInt64(address), size = UInt64(size), perms = perms)
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
    begin_addr::UInt64,
    until_addr::UInt64,
    μs_timeout::UInt64,
    inst_count::UInt64,
)::Err
    uc_emu_start = Libdl.dlsym(LIBUNICORN, :uc_emu_start)
    ccall(
        uc_emu_start,
        Err,
        (UcHandle, UInt64, UInt64, UInt64, UInt),
        emu.handle,
        begin_addr,
        until_addr,
        μs_timeout,
        inst_count,
    )

end

function emu_start(
    emu::Emulator;
    begin_addr = 0,
    until_addr = 0,
    μs_timeout = 0,
    inst_count = 0,
)::Err
    emu_start(
        emu,
        UInt64(begin_addr),
        UInt64(until_addr),
        UInt64(μs_timeout),
        UInt64(inst_count),
    )
end

function mem_write(handle::UcHandle; address::UInt64, bytes::Vector{UInt8})::UInt
    size = length(bytes)
    ptr = pointer(bytes)
    uc_mem_write = Libdl.dlsym(LIBUNICORN, :uc_mem_write)
    check(ccall(
        uc_mem_write,
        Err,
        (UcHandle, UInt64, (Ptr{UInt8}), UInt),
        handle,
        address,
        ptr,
        size,
    ))
    size
end

function mem_write(emu::Emulator; address::UInt64, bytes::Vector{UInt8})::UInt
    mem_write(emu.handle, address = address, bytes = bytes)
end

function reg_read(handle::UcHandle, regid::Int)::UInt64

    value = Ref{UInt64}()
    value[] = 0x0000_0000_0000_0000

    uc_reg_read = Libdl.dlsym(LIBUNICORN, :uc_reg_read)
    check(ccall(uc_reg_read, Err, (UcHandle, Int, Ptr{UInt64}), handle, regid, value))

    return value[]

end

function reg_read(handle::UcHandle, regid::R)::UInt64 where { R <: Register }
    reg_read(handle, Int(regid))
end

function reg_read(emu::Emulator, regid::R)::UInt64 where { R <: Register } 
    reg_read(emu.handle, regid)
end

# FIXME: this doesn't work yet
# function reg_read_batch(handle::UcHandle, regids::Vector{Int})
#     count = length(regids)
#     values = Ref{Ptr{UInt64}}() #Vector{UInt64}(undef, count)
# 
#     uc_reg_read_batch = Libdl.dlsym(LIBUNICORN, :uc_reg_read_batch)
# 
#     check(ccall(
#         uc_reg_read_batch,
#         Err,
#         (UcHandle, Ptr{Int}, Ref{Ptr{UInt64}}, Int),
#         handle,
#         pointer(regids),
#         values,
#         count,
#     ))
# 
#     values
# 
# end
# 
# function reg_read_batch(emu::Emulator, regids::Vector{R}) where { R <: Register }
#     reg_read_batch(emu.handle, [Int(r) for r in regids])
# end
# 
function reg_write(handle::UcHandle, regid::R, value::T) where {T<:Integer,R<:Register}

    value = UInt64(value)
    regid = Int(regid)
    uc_reg_write = Libdl.dlsym(LIBUNICORN, :uc_reg_write)
    check(ccall(uc_reg_write, Err, (UcHandle, Int, Ref{UInt64}), handle, regid, Ref(value)))

end

function reg_write(emu::Emulator, regid::R, value::T) where {T<:Integer,R<:Register}
    reg_write(emu.handle, regid, value)
end


function mem_read(handle::UcHandle, address::UInt64, size::UInt64)::Vector{UInt8}

    bytes = Vector{UInt8}(undef, size)

    uc_mem_read = Libdl.dlsym(LIBUNICORN, :uc_mem_read)
    check(ccall(
        uc_mem_read,
        Err,
        (UcHandle, UInt64, Ptr{UInt8}, UInt64),
        handle,
        address,
        pointer(bytes),
        size,
    ))

    bytes
end

function mem_read(emu::Emulator; address = 0, size = 0)::Vector{UInt8}
    mem_read(emu.handle, UInt64(address), UInt64(size))
end

# This method is primarily to be used in hooks, where we have access only
# to the bare UC handle, and not the Emulator wrapper struct.
function uc_stop(handle::UcHandle)
    uc_emu_stop = Libdl.dlsym(LIBUNICORN, :uc_emu_stop)
    check(ccall(uc_emu_stop, Err, (UcHandle,), handle))
end


mutable struct MemRegion
    from::UInt64
    to::UInt64
    perms::Perm
    MemRegion() = new(0, 0, Perm(0))
end

function mem_regions(handle::UcHandle) #::Vector{MemRegion}

    regions = Ref{Ptr{MemRegion}}()
    count = Ref{UInt32}()
    count[] = 0x0000_0000

    uc_mem_regions = Libdl.dlsym(LIBUNICORN, :uc_mem_regions)
    check(ccall(
        uc_mem_regions,
        Err,
        (UcHandle, Ref{Ptr{MemRegion}}, Ptr{UInt32}),
        handle,
        regions,
        count,
    ))

    [unsafe_load(regions[], i) for i = 1:count[]]
end

function mem_regions(emu::Emulator)
    mem_regions(emu.handle)
end

# TODO:
# - uc_mem_regions
# - hooks!
# - maybe batch read/write

# End of Module
end
