module Unicorn

# TODO: https://discourse.julialang.org/t/avoid-gc-freeing-ptr-nothing/38664/8
# I think GC is occasionally cleaning up some of my C-allocated void pointers.

using Libdl
using unicorn_jll

__precompile__()

LIBUNICORN = nothing
function __init__()
    global LIBUNICORN
    LIBUNICORN = unicorn_jll.libunicorn_handle
end

export ARM,
    ARM64,
    Arch,
    Emulator,
    HookType,
    M68K,
    MIPS,
    Mode,
    Perm,
    SPARC,
    UcException,
    UcHandle,
    X86,
    code_hook_add,
    emu_start,
    interrupt_hook_add,
    mem_hook_add,
    mem_map,
    mem_regions,
    mem_write,
    reg_read,
    reg_write,
    uc_stop,
    unicorn_version


include("./architectures/ARM.jl")
include("./architectures/ARM64.jl")
include("./architectures/M68K.jl")
include("./architectures/MIPS.jl")
include("./architectures/SPARC.jl")
include("./architectures/X86.jl")

const Register = Union{
    ARM.Register.t,
    ARM64.Register.t,
    M68K.Register.t,
    MIPS.Register.t,
    SPARC.Register.t,
    X86.Register.t,
}

module Perm
using BitFlags
@bitflag t::Cuint begin
    NONE = 0x0
    READ = 0x1
    WRITE = 0x2
    EXEC = 0x4
end
ALL = READ | WRITE | EXEC
end

# I want dot access to enum variants, so I'm going to adopt the OCaml
# naming convention of naming the wrapping module after the enum, and
# naming the enum itself `t`. Do not unwrap these modules with `Using`.
module Arch
@enum t begin
    ARM = 0x1
    ARM64 = 0x2
    MIPS = 0x3
    X86 = 0x4
    PPC = 0x5
    SPARC = 0x6
    M68K = 0x7
    MAX = 0x8
end
end

# TODO: add the rest of the modes
module Mode
@enum t begin
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

module UcError
@enum t begin
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
end


struct UcException <: Exception
    code::UcError.t
end


module HookType
using BitFlags
@bitflag t::Cuint begin
    INTR = 1
    INSN = 1 << 1
    CODE = 1 << 2
    BLOCK = 1 << 3
    MEM_READ_UNMAPPED = 1 << 4
    MEM_WRITE_UNMAPPED = 1 << 5
    MEM_FETCH_UNMAPPED = 1 << 6
    MEM_READ_PROT = 1 << 7
    MEM_WRITE_PROT = 1 << 8
    MEM_FETCH_PROT = 1 << 9
    MEM_READ = 1 << 10
    MEM_WRITE = 1 << 11
    MEM_FETCH = 1 << 12
    MEM_READ_AFTER = 1 << 13
    INSN_INVALID = 1 << 14
end
end




const UcHandle = Ptr{Cvoid}

function uc_close(uc::UcHandle)
    #@async println("Closing and freeing unicorn emulator at $(uc)...")
    uc_close = Libdl.dlsym(LIBUNICORN, :uc_close)
    ccall(uc_close, Nothing, (UcHandle,), uc)
end


# The unicorn emulator object
mutable struct Emulator
    arch::Arch.t
    mode::Mode.t
    handle::Ref{UcHandle}
    hooks::Vector{Csize_t}

    # Constructor
    Emulator(arch::Arch.t, mode::Mode.t) = begin
        uc = Ref{UcHandle}()

        uc_open = Libdl.dlsym(LIBUNICORN, :uc_open)
        check(ccall(uc_open, UcError.t, (UInt, UInt, Ref{UcHandle}), arch, mode, uc))
        emu = new(arch, mode, uc, [])
        finalizer(e -> uc_close(e.handle[]), emu)
        return emu
    end
end

function check(result::UcError.t)
    if result != UcError.OK
        throw(UcException(result))
    end
end

"""
Map memory in for emulation.
This API adds a memory region that can be used by emulation.

- uc: handle returned by uc_open()
- address: starting address of the new memory region to be mapped in.
   This address must be aligned to 4KB, or this will return with UC_ERR_ARG error.
- size: size of the new memory region to be mapped in.
   This size must be multiple of 4KB, or this will return with UC_ERR_ARG error.
- perms: Permissions for the newly mapped region.
   This must be some combination of UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
   or this will return with UC_ERR_ARG error.
"""
function mem_map(
    handle::UcHandle;
    address::UInt64 = 0x0000_0000_0000_0000,
    size::UInt = 0x0000_0000_0000_1000,
    perms::Perm.t = Perm.ALL,
)
    uc_mem_map = Libdl.dlsym(LIBUNICORN, :uc_mem_map)
    check(ccall(
        uc_mem_map,
        UcError.t,
        (UcHandle, UInt64, UInt, UInt32),
        handle,
        address,
        size,
        perms,
    ))
end

function mem_map(emu::Emulator; address = 0, size = 4096, perms::Perm.t = Perm.ALL)
    mem_map(emu.handle[], address = UInt64(address), size = UInt64(size), perms = perms)
end

"""
Emulate machine code in a specific duration of time.
- emu: handle returned by uc_open()
- begin_addr: address where emulation starts
- until_addr: address where emulation stops (i.e when this address is hit)
- μs_timeout: duration to emulate the code (in microseconds). When this value is 0,
       we will emulate the code in infinite time, until the code is finished.
- inst_count: the number of instructions to be emulated. When this value is 0,
       we will emulate all the code available, until the code is finished.

- return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
  for detailed error).
"""
function emu_start(
    emu::Emulator,
    begin_addr::UInt64,
    until_addr::UInt64,
    μs_timeout::UInt64,
    inst_count::UInt64,
)::UcError.t
    uc_emu_start = Libdl.dlsym(LIBUNICORN, :uc_emu_start)
    ccall(
        uc_emu_start,
        UcError.t,
        (UcHandle, UInt64, UInt64, UInt64, UInt),
        emu.handle[],
        begin_addr,
        until_addr,
        μs_timeout,
        inst_count,
    )

end

function emu_start(
    emu::Emulator;
    begin_addr::M = 0,
    until_addr::N = 0,
    μs_timeout::O = 0,
    inst_count::P = 0,
)::UcError.t where {M<:Integer,N<:Integer,O<:Integer,P<:Integer}
    emu_start(
        emu,
        UInt64(begin_addr),
        UInt64(until_addr),
        UInt64(μs_timeout),
        UInt64(inst_count),
    )
end

function mem_write(handle::UcHandle; address::UInt64, bytes::Vector{UInt8})
    size = length(bytes)
    ptr = pointer(bytes)
    uc_mem_write = Libdl.dlsym(LIBUNICORN, :uc_mem_write)
    check(ccall(
        uc_mem_write,
        UcError.t,
        (UcHandle, UInt64, (Ptr{UInt8}), UInt),
        handle,
        address,
        ptr,
        size,
    ))
end

"""
Write an array of bytes to the emulator's memory. Note that the memory range
written to must be mapped, beforehand, using the `mem_map()` method.

This method will throw a `UcException` if an attempt is made to write to
unmapped memory. 
"""
function mem_write(emu::Emulator; address::N, bytes::Vector{UInt8}) where {N<:Integer}
    mem_write(emu.handle[], address = UInt64(address), bytes = bytes)
end


function reg_read(handle::UcHandle, regid::Int)::UInt64

    value = Ref{UInt64}()
    value[] = 0x0000_0000_0000_0000

    uc_reg_read = Libdl.dlsym(LIBUNICORN, :uc_reg_read)
    check(ccall(uc_reg_read, UcError.t, (UcHandle, Int, Ptr{UInt64}), handle, regid, value))

    return value[]

end

function reg_read(handle::UcHandle, regid::R)::UInt64 where {R<:Register}
    reg_read(handle, Int(regid))
end

"""
Read an emulator register. The caller is responsible for ensuring that the
appropriate architecture's register identifiers are used.

This method may throw a `UcException` if something goes wrong.
"""
function reg_read(emu::Emulator, regid::R)::UInt64 where {R<:Register}
    reg_read(emu.handle[], regid)
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
#         UcError.t,
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
#     reg_read_batch(emu.handle[], [Int(r) for r in regids])
# end

function reg_write(handle::UcHandle, regid::R, value::T) where {T<:Integer,R<:Register}
    value = UInt64(value)
    regid = Int(regid)
    uc_reg_write = Libdl.dlsym(LIBUNICORN, :uc_reg_write)
    check(ccall(
        uc_reg_write,
        UcError.t,
        (UcHandle, Int, Ref{UInt64}),
        handle,
        regid,
        Ref(value),
    ))
end

"""
Write a value to an emulator register. May throw a `UcException` if misused.
"""
function reg_write(emu::Emulator; register::R, value::T) where {T<:Integer,R<:Register}
    reg_write(emu.handle[], register, value)
end


function mem_read(handle::UcHandle, address::UInt64, size::UInt64)::Vector{UInt8}

    bytes = Vector{UInt8}(undef, size)

    uc_mem_read = Libdl.dlsym(LIBUNICORN, :uc_mem_read)
    check(ccall(
        uc_mem_read,
        UcError.t,
        (UcHandle, UInt64, Ptr{UInt8}, UInt64),
        handle,
        address,
        pointer(bytes),
        size,
    ))

    bytes
end

"""
Read `size` bytes from `address` in emulator memory.
"""
function mem_read(
    emu::Emulator;
    address::M = 0,
    size::N = 0,
)::Vector{UInt8} where {M<:Integer,N<:Integer}
    mem_read(emu.handle[], UInt64(address), UInt64(size))
end

# This method is primarily to be used in hooks, where we have access only
# to the bare UC handle, and not the Emulator wrapper struct.
function uc_stop(handle::UcHandle)
    uc_emu_stop = Libdl.dlsym(LIBUNICORN, :uc_emu_stop)
    check(ccall(uc_emu_stop, UcError.t, (UcHandle,), handle))
end


mutable struct MemRegion
    from::UInt64
    to::UInt64
    perms::Perm.t
    MemRegion() = new(0, 0, Perm.t(0))
end

function mem_regions(handle::UcHandle) #::Vector{MemRegion}

    regions = Ref{Ptr{MemRegion}}()
    count = Ref{UInt32}()
    count[] = 0x0000_0000

    uc_mem_regions = Libdl.dlsym(LIBUNICORN, :uc_mem_regions)
    check(ccall(
        uc_mem_regions,
        UcError.t,
        (UcHandle, Ref{Ptr{MemRegion}}, Ptr{UInt32}),
        handle,
        regions,
        count,
    ))

    # TODO: figure out if we need to free thse with `uc_free()`
    # I'm not really sure. if so, we should free them here, once we've
    # copied their data out into julia structs. 
    [unsafe_load(regions[], i) for i = 1:count[]]
end

function mem_regions(emu::Emulator)
    mem_regions(emu.handle[])
end

const HookHandle = Csize_t

function hook_add(
    handle::UcHandle;
    type::HookType.t,
    begin_addr::N,
    until_addr::M,
    c_callback::Ptr{Cvoid},
    user_data = Ref{Ptr{Cvoid}}()[],
) where {M<:Integer,N<:Integer}

    # do we need to do anything with user data? is it good enough if the
    # callback is a closure?
    uc_hook_add = Libdl.dlsym(LIBUNICORN, :uc_hook_add)
    hook_handle = Ref{Csize_t}(0)
    check(ccall(
        uc_hook_add,
        UcError.t,
        (UcHandle, Ref{Csize_t}, Cuint, Ptr{Cvoid}, Ptr{Cvoid}, UInt64, UInt64),
        handle,
        hook_handle,
        type,
        c_callback,
        user_data,
        begin_addr,
        until_addr,
    ))

    hook_handle[]
end

"""
Code hook callbacks must be void functions with three parameters:
- the unicorn engine handle, of type `UcHandle`
- the address, of type `Culonglong` (`UInt64`)
- the size of the current instruction or block, of type `Cuint` (`UInt32`)
"""
function code_hook_add(
    emu::Emulator;
    type::HookType.t = HookType.CODE,
    begin_addr::N = 1,
    until_addr::M = 0,
    callback::Function, # Must have the signature $CODE_HOOK_SIGNATURE
)::Csize_t where {M<:Integer,N<:Integer}

    @assert type == HookType.CODE || type == HookType.BLOCK "Invalid hook type."

    c_callback = eval(:(@cfunction($callback, Cvoid, (UcHandle, Culonglong, Cuint))))

    hh = hook_add(
        emu.handle[],
        type = type,
        begin_addr = begin_addr,
        until_addr = until_addr,
        c_callback = c_callback,
    )

    push!(emu.hooks, hh)

    hh
end

"""
Interrupt hook callbacks should take two parameters:
- an engine handle, of type `UcHandle`, and
- the interrupt number, of type `Cuint` (`UInt32`)
"""
function interrupt_hook_add(
    emu::Emulator;
    begin_addr::M = 1,
    until_addr::N = 0,
    callback::Function,
)::Csize_t where {M<:Integer,N<:Integer}

    c_callback = eval(:(@cfunction($callback, Cvoid, (UcHandle, Cuint))))

    hh = hook_add(
        emu.handle[],
        type = HookType.INTR,
        begin_addr = begin_addr,
        until_addr = until_addr,
        c_callback = c_callback,
    )

    push!(emu.hooks, hh)

    hh

end

"""
Callbacks for invalid instruction hooks take one parameter,
the handle of the unicorn engine (`UcHandle`), and return
a `Bool`: `true` to continue execution, or `false` to stop
the program with an invalid instruction error.
"""
function invalid_inst_hook_add(
    emu::Emulator;
    begin_addr::M = 1,
    until_addr::N = 0,
    callback::Function,
)::Csize_t where {M<:Integer,N<:Integer}

    c_callback = eval(:(@cfunction($callback, Bool, (UcHandle,))))

    hh = hook_add(
        emu.handle[],
        type = HookType.INSN_INVALID,
        begin_addr = begin_addr,
        until_addr = until_addr,
        c_callback = c_callback,
    )

    push!(emu.hooks, hh)

    hh
end

# TODO: Find out if other instruction code callbacks are supported
"""
Callback functions for tracing `IN` or `OUT` instructions of the X86 take
four parameters:
- a handle to the unicorn emulator engine, of type `UcHandle`
- a port number, of type `Cuint` (`UInt32`)
- a data size (1/2/4) to be written to this port
- a data value, of type `Cuint`, to be written to this port

Currently, the only instructions supported are `IN` and `OUT`. 
Attempts to use other instruction codes will result in Unicorn
returning an error code, which will throw `UcException(HOOK::t = 9)`.
"""
function x86_instruction_hook_add(
    emu::Emulator;
    begin_addr::M = 1,
    until_addr::N = 0,
    instruction_id::X86.Instruction.t,
    callback::Function,
)::Csize_t where {M<:Integer,N<:Integer}

    c_callback = eval(:(@cfunction($callback, Cvoid, (UcHandle, Cuint, Cint, Cuint))))

    uc_hook_add = Libdl.dlsym(LIBUNICORN, :uc_hook_add)
    hook_handle = Ref{Csize_t}(0)

    user_data = Ref{Ptr{Cvoid}}()[]

    check(ccall(
        uc_hook_add,
        UcError.t,
        (UcHandle, Ref{Csize_t}, Cuint, Ptr{Cvoid}, Ptr{Cvoid}, UInt64, UInt64, Cuint),
        emu.handle[],
        hook_handle,
        HookType.INSN,
        c_callback,
        user_data,
        begin_addr,
        until_addr,
        instruction_id,
    ))

    push!(emu.hooks, hook_handle[])

    hook_handle[]
end

module MemoryAccess
@enum t begin
    READ = 16
    WRITE
    FETCH
    READ_UNMAPPED
    WRITE_UNMAPPED
    FETCH_UNMAPPED
    WRITE_PROT
    READ_PROT
    FETCH_PROT
    READ_AFTER
end
end

"""
Callback functions for hooking memory (READ, WRITE, & FETCH)
should take five parameters. Note that FETCH hooks don't 
appear to be currently supported by Unicorn (and this oversight
appears to be undocumented).

- handle of the unicorn emulator, `UcHandle`
- type of memory action (`MemoryAccess.t`)
- address of the code being executed, `UInt64`
- size of data being read from or written to memory, `Cint`
- value of data being written to memory, `Int64`

These callbacks should return `true`, unless the type of memory access
being hooked are invalid accesses, in which case a `false` can be 
returned by the callback to stop execution.
"""
function mem_hook_add(
    emu::Emulator;
    begin_addr::M = 1,
    until_addr::N = 0,
    access_type::HookType.t = HookType.MEM_READ,
    callback::Function,
)::Csize_t where {M<:Integer,N<:Integer}

    ret_type = Cvoid

    if access_type in [
        HookType.MEM_FETCH_PROT,
        HookType.MEM_FETCH_UNMAPPED,
        HookType.MEM_READ_PROT,
        HookType.MEM_READ_UNMAPPED,
        HookType.MEM_WRITE_PROT,
        HookType.MEM_WRITE_UNMAPPED,
    ]
        ret_type = Bool
    end

    c_callback =
        eval(:(@cfunction($callback, $ret_type, (UcHandle, Cuint, UInt64, Cint, Int64))))

    hh = hook_add(
        emu.handle[],
        type = access_type,
        begin_addr = begin_addr,
        until_addr = until_addr,
        c_callback = c_callback,
    )

    push!(emu.hooks, hh)

    hh

end

function hook_del(uc_handle::UcHandle, hook_handle::Csize_t)

    uc_hook_del = Libdl.dlsym(LIBUNICORN, :uc_hook_del)

    check(ccall(uc_hook_del, UcError.t, (UcHandle, Csize_t), uc_handle, hook_handle))

end

function hook_del(emu::Emulator, hook_handle::Csize_t)

    hook_del(emu.handle[], hook_handle)
    filter!(h -> h != hook_handle, emu.hooks)

    return

end

function delete_all_hooks(emu::Emulator)

    while length(emu.hooks) > 0
        hook_del(emu.handle[], pop!(emu.hooks))
    end

end

"""
Returns the current version number of the Unicorn C library.
"""
function unicorn_version()
    uc_version = Libdl.dlsym(LIBUNICORN, :uc_version)
    val = ccall(uc_version, UInt32, (Ptr{Cuint}, Ptr{Cuint}), Ptr{Cuint}(0), Ptr{Cuint}(0))
    minor = val & 0x0F
    major = (val >> 8) & 0x0F
    return VersionNumber(major, minor)
end

function quick()
    emu = Emulator(Arch.X86, Mode.MODE_64)
    mem_map(emu)
    mem_write(emu, address = 0, bytes = rand(UInt8, 0x1000))
    return emu
end

### End of module
end
