///! Platform host that tests effectful functions writing to stdout and stderr.
const std = @import("std");
const builtin = @import("builtin");
const builtins = @import("builtins");

/// Number of stack frames to capture for leak tracking
const STACK_TRACE_FRAMES = 8;

/// Allocation info for leak tracking
const AllocationInfo = struct {
    stack_trace: [STACK_TRACE_FRAMES]usize,
    size: usize,
};

/// Leak-tracking allocator that uses atos for symbolication on macOS
const LeakTrackingAllocator = struct {
    allocations: std.AutoHashMap(usize, AllocationInfo),
    backing_allocator: std.mem.Allocator,

    pub fn init(backing: std.mem.Allocator) LeakTrackingAllocator {
        return .{
            .allocations = std.AutoHashMap(usize, AllocationInfo).init(backing),
            .backing_allocator = backing,
        };
    }

    pub fn deinit(self: *LeakTrackingAllocator) void {
        self.allocations.deinit();
    }

    pub fn allocator(self: *LeakTrackingAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *LeakTrackingAllocator = @ptrCast(@alignCast(ctx));
        const result = self.backing_allocator.rawAlloc(len, alignment, ret_addr) orelse return null;

        // Capture stack trace
        var info = AllocationInfo{
            .stack_trace = undefined,
            .size = len,
        };

        var stack_iter = std.debug.StackIterator.init(ret_addr, null);
        var i: usize = 0;
        while (i < STACK_TRACE_FRAMES) : (i += 1) {
            info.stack_trace[i] = stack_iter.next() orelse 0;
        }

        self.allocations.put(@intFromPtr(result), info) catch {};
        return result;
    }

    fn resize(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *LeakTrackingAllocator = @ptrCast(@alignCast(ctx));
        return self.backing_allocator.rawResize(buf, alignment, new_len, ret_addr);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *LeakTrackingAllocator = @ptrCast(@alignCast(ctx));
        const result = self.backing_allocator.rawRemap(memory, alignment, new_len, ret_addr) orelse return null;

        // Update tracking if pointer changed
        if (result != memory.ptr) {
            _ = self.allocations.remove(@intFromPtr(memory.ptr));

            var info = AllocationInfo{
                .stack_trace = undefined,
                .size = new_len,
            };
            var stack_iter = std.debug.StackIterator.init(ret_addr, null);
            var i: usize = 0;
            while (i < STACK_TRACE_FRAMES) : (i += 1) {
                info.stack_trace[i] = stack_iter.next() orelse 0;
            }
            self.allocations.put(@intFromPtr(result), info) catch {};
        }

        return result;
    }

    fn free(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *LeakTrackingAllocator = @ptrCast(@alignCast(ctx));
        _ = self.allocations.remove(@intFromPtr(buf.ptr));
        self.backing_allocator.rawFree(buf, alignment, ret_addr);
    }

    /// Check for leaks and print stack traces using atos on macOS
    pub fn checkLeaks(self: *LeakTrackingAllocator) bool {
        if (self.allocations.count() == 0) {
            return false; // No leaks
        }

        const stderr_file: std.fs.File = .stderr();
        var msg_buf: [256]u8 = undefined;
        const header = std.fmt.bufPrint(&msg_buf, "\n\x1b[31mMemory leaks detected: {d} allocation(s) not freed\x1b[0m\n\n", .{self.allocations.count()}) catch return true;
        stderr_file.writeAll(header) catch {};

        var iter = self.allocations.iterator();
        var leak_num: usize = 1;
        while (iter.next()) |entry| {
            const ptr = entry.key_ptr.*;
            const info = entry.value_ptr.*;

            // Print leak header: "Leak #N: M bytes at 0xPTR\n"
            const leak_header = std.fmt.bufPrint(&msg_buf, "Leak #{d}: {d} bytes at 0x{x}\n", .{ leak_num, info.size, ptr }) catch continue;
            stderr_file.writeAll(leak_header) catch {};

            printStackTrace(info.stack_trace[0..], stderr_file);
            stderr_file.writeAll("\n") catch {};
            leak_num += 1;
        }

        return true; // Leaks found
    }
};

/// Print stack trace, using atos on macOS for proper symbolication
fn printStackTrace(addresses: []const usize, file: std.fs.File) void {
    if (builtin.os.tag == .macos) {
        printStackTraceWithAtos(addresses, file);
    } else {
        // Fallback - just print hex addresses
        var addr_buf: [64]u8 = undefined;
        for (addresses) |addr| {
            if (addr == 0) break;
            const line = std.fmt.bufPrint(&addr_buf, "    0x{x}\n", .{addr}) catch continue;
            file.writeAll(line) catch {};
        }
    }
}

/// Use atos to resolve addresses on macOS
fn printStackTraceWithAtos(addresses: []const usize, file: std.fs.File) void {
    // Get executable path
    var path_buf: [std.fs.max_path_bytes:0]u8 = undefined;
    var path_len: u32 = @intCast(path_buf.len);
    if (std.c._NSGetExecutablePath(&path_buf, &path_len) != 0) {
        file.writeAll("    (could not get executable path)\n") catch {};
        return;
    }
    const exe_path = std.mem.sliceTo(&path_buf, 0);

    // Get ASLR slide for main executable
    const slide = std.c._dyld_get_image_vmaddr_slide(0);

    // Count valid addresses
    var addr_count: usize = 0;
    for (addresses) |addr| {
        if (addr != 0) addr_count += 1;
    }
    if (addr_count == 0) return;

    // Build argument slices - store strings in fixed buffers
    var addr_strings: [STACK_TRACE_FRAMES][24]u8 = undefined;
    var addr_slices: [STACK_TRACE_FRAMES][]const u8 = undefined;
    var argv: [STACK_TRACE_FRAMES + 5][]const u8 = undefined;
    var argc: usize = 0;

    argv[argc] = "atos";
    argc += 1;
    argv[argc] = "-o";
    argc += 1;
    argv[argc] = exe_path;
    argc += 1;
    argv[argc] = "-l";
    argc += 1;

    // Format load address as 0x...
    const load_addr = 0x100000000 + @as(usize, @bitCast(slide));
    var load_addr_buf: [26]u8 = undefined;
    const load_addr_str = std.fmt.bufPrint(&load_addr_buf, "0x{x}", .{load_addr}) catch "0x0";
    argv[argc] = load_addr_str;
    argc += 1;

    // Add addresses
    for (addresses, 0..) |addr, i| {
        if (addr == 0) break;
        const addr_str = std.fmt.bufPrint(&addr_strings[i], "0x{x}", .{addr}) catch continue;
        addr_slices[i] = addr_str;
        argv[argc] = addr_slices[i];
        argc += 1;
    }

    // Run atos
    var child = std.process.Child.init(argv[0..argc], std.heap.page_allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    child.spawn() catch {
        // Fallback if atos not available - just print hex addresses
        var addr_buf: [64]u8 = undefined;
        for (addresses) |addr| {
            if (addr == 0) break;
            const line = std.fmt.bufPrint(&addr_buf, "    0x{x}\n", .{addr}) catch continue;
            file.writeAll(line) catch {};
        }
        return;
    };

    // Read atos output
    const stdout = child.stdout orelse return;
    var output_buf: [4096]u8 = undefined;
    const bytes_read = stdout.read(&output_buf) catch 0;

    _ = child.wait() catch {};

    if (bytes_read > 0) {
        // Parse and print each line with indentation
        var lines = std.mem.splitScalar(u8, output_buf[0..bytes_read], '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            file.writeAll("    ") catch {};
            file.writeAll(line) catch {};
            file.writeAll("\n") catch {};
        }
    }
}

/// Host environment
const HostEnv = struct {
    leak_tracker: LeakTrackingAllocator,
};

/// Roc allocation function with size-tracking metadata
fn rocAllocFn(roc_alloc: *builtins.host_abi.RocAlloc, env: *anyopaque) callconv(.c) void {
    const host: *HostEnv = @ptrCast(@alignCast(env));
    const allocator = host.leak_tracker.allocator();

    const align_enum = std.mem.Alignment.fromByteUnits(@as(usize, @intCast(roc_alloc.alignment)));

    // Calculate additional bytes needed to store the size
    const size_storage_bytes = @max(roc_alloc.alignment, @alignOf(usize));
    const total_size = roc_alloc.length + size_storage_bytes;

    // Allocate memory including space for size metadata
    const result = allocator.rawAlloc(total_size, align_enum, @returnAddress());

    const base_ptr = result orelse {
        const stderr: std.fs.File = .stderr();
        stderr.writeAll("\x1b[31mHost error:\x1b[0m allocation failed, out of memory\n") catch {};
        std.process.exit(1);
    };

    // Store the total size (including metadata) right before the user data
    const size_ptr: *usize = @ptrFromInt(@intFromPtr(base_ptr) + size_storage_bytes - @sizeOf(usize));
    size_ptr.* = total_size;

    // Return pointer to the user data (after the size metadata)
    roc_alloc.answer = @ptrFromInt(@intFromPtr(base_ptr) + size_storage_bytes);

    std.log.debug("[ALLOC] ptr=0x{x} size={d} align={d}", .{ @intFromPtr(roc_alloc.answer), roc_alloc.length, roc_alloc.alignment });
}

/// Roc deallocation function with size-tracking metadata
fn rocDeallocFn(roc_dealloc: *builtins.host_abi.RocDealloc, env: *anyopaque) callconv(.c) void {
    std.log.debug("[DEALLOC] ptr=0x{x} align={d}", .{ @intFromPtr(roc_dealloc.ptr), roc_dealloc.alignment });

    const host: *HostEnv = @ptrCast(@alignCast(env));
    const allocator = host.leak_tracker.allocator();

    // Calculate where the size metadata is stored
    const size_storage_bytes = @max(roc_dealloc.alignment, @alignOf(usize));
    const size_ptr: *const usize = @ptrFromInt(@intFromPtr(roc_dealloc.ptr) - @sizeOf(usize));

    // Read the total size from metadata
    const total_size = size_ptr.*;

    // Calculate the base pointer (start of actual allocation)
    const base_ptr: [*]u8 = @ptrFromInt(@intFromPtr(roc_dealloc.ptr) - size_storage_bytes);

    // Calculate alignment
    const log2_align = std.math.log2_int(u32, @intCast(roc_dealloc.alignment));
    const align_enum: std.mem.Alignment = @enumFromInt(log2_align);

    // Free the memory (including the size metadata)
    const slice = @as([*]u8, @ptrCast(base_ptr))[0..total_size];
    allocator.rawFree(slice, align_enum, @returnAddress());
}

/// Roc reallocation function with size-tracking metadata
fn rocReallocFn(roc_realloc: *builtins.host_abi.RocRealloc, env: *anyopaque) callconv(.c) void {
    const host: *HostEnv = @ptrCast(@alignCast(env));
    const allocator = host.leak_tracker.allocator();

    // Calculate where the size metadata is stored for the old allocation
    const size_storage_bytes = @max(roc_realloc.alignment, @alignOf(usize));
    const old_size_ptr: *const usize = @ptrFromInt(@intFromPtr(roc_realloc.answer) - @sizeOf(usize));

    // Read the old total size from metadata
    const old_total_size = old_size_ptr.*;

    // Calculate the old base pointer (start of actual allocation)
    const old_base_ptr: [*]u8 = @ptrFromInt(@intFromPtr(roc_realloc.answer) - size_storage_bytes);

    // Calculate new total size needed
    const new_total_size = roc_realloc.new_length + size_storage_bytes;

    // Perform reallocation
    const old_slice = @as([*]u8, @ptrCast(old_base_ptr))[0..old_total_size];
    const new_slice = allocator.realloc(old_slice, new_total_size) catch {
        const stderr: std.fs.File = .stderr();
        stderr.writeAll("\x1b[31mHost error:\x1b[0m reallocation failed, out of memory\n") catch {};
        std.process.exit(1);
    };

    // Store the new total size in the metadata
    const new_size_ptr: *usize = @ptrFromInt(@intFromPtr(new_slice.ptr) + size_storage_bytes - @sizeOf(usize));
    new_size_ptr.* = new_total_size;

    // Return pointer to the user data (after the size metadata)
    roc_realloc.answer = @ptrFromInt(@intFromPtr(new_slice.ptr) + size_storage_bytes);

    std.log.debug("[REALLOC] old=0x{x} new=0x{x} new_size={d}", .{ @intFromPtr(old_base_ptr) + size_storage_bytes, @intFromPtr(roc_realloc.answer), roc_realloc.new_length });
}

/// Roc debug function
fn rocDbgFn(roc_dbg: *const builtins.host_abi.RocDbg, env: *anyopaque) callconv(.c) void {
    _ = env;
    const message = roc_dbg.utf8_bytes[0..roc_dbg.len];
    std.log.debug("\x1b[33mRoc dbg:\x1b[0m {s}", .{message});
}

/// Roc expect failed function
fn rocExpectFailedFn(roc_expect: *const builtins.host_abi.RocExpectFailed, env: *anyopaque) callconv(.c) void {
    _ = env;
    const source_bytes = roc_expect.utf8_bytes[0..roc_expect.len];
    const trimmed = std.mem.trim(u8, source_bytes, " \t\n\r");
    std.log.debug("\x1b[33mExpect failed:\x1b[0m {s}", .{trimmed});
}

/// Roc crashed function
fn rocCrashedFn(roc_crashed: *const builtins.host_abi.RocCrashed, env: *anyopaque) callconv(.c) noreturn {
    _ = env;
    const message = roc_crashed.utf8_bytes[0..roc_crashed.len];
    const stderr: std.fs.File = .stderr();
    var buf: [256]u8 = undefined;
    var w = stderr.writer(&buf);
    w.interface.print("\n\x1b[31mRoc crashed:\x1b[0m {s}\n", .{message}) catch {};
    w.interface.flush() catch {};
    std.process.exit(1);
}

// External symbols provided by the Roc runtime object file
// Follows RocCall ABI: ops, ret_ptr, then argument pointers
extern fn roc__main_for_host(ops: *builtins.host_abi.RocOps, ret_ptr: *anyopaque, arg_ptr: ?*anyopaque) callconv(.c) void;

// OS-specific entry point handling
comptime {
    // Export main for all platforms
    @export(&main, .{ .name = "main" });

    // Windows MinGW/MSVCRT compatibility: export __main stub
    if (@import("builtin").os.tag == .windows) {
        @export(&__main, .{ .name = "__main" });
    }
}

// Windows MinGW/MSVCRT compatibility stub
// The C runtime on Windows calls __main from main for constructor initialization
fn __main() callconv(.c) void {}

// C compatible main for runtime
fn main(argc: c_int, argv: [*][*:0]u8) callconv(.c) c_int {
    return platform_main(@intCast(argc), argv);
}

// Use the actual types from builtins
const RocStr = builtins.str.RocStr;
const RocList = builtins.list.RocList;

/// Hosted function: Stderr.line! (index 0 - sorted alphabetically)
/// Follows RocCall ABI: (ops, ret_ptr, args_ptr)
/// Returns {} and takes Str as argument
fn hostedStderrLine(ops: *builtins.host_abi.RocOps, ret_ptr: *anyopaque, args_ptr: *anyopaque) callconv(.c) void {
    _ = ops;
    _ = ret_ptr; // Return value is {} which is zero-sized

    // Arguments struct for single Str parameter
    const Args = extern struct { str: RocStr };
    const args: *Args = @ptrCast(@alignCast(args_ptr));

    const message = args.str.asSlice();
    const stderr: std.fs.File = .stderr();
    stderr.writeAll(message) catch {};
    stderr.writeAll("\n") catch {};
}

/// Hosted function: Stdin.line! (index 1 - sorted alphabetically)
/// Follows RocCall ABI: (ops, ret_ptr, args_ptr)
/// Returns Str and takes {} as argument
fn hostedStdinLine(ops: *builtins.host_abi.RocOps, ret_ptr: *anyopaque, args_ptr: *anyopaque) callconv(.c) void {
    _ = args_ptr; // Argument is {} which is zero-sized

    // Read a line from stdin
    var buffer: [4096]u8 = undefined;
    const stdin_file: std.fs.File = .stdin();
    const bytes_read = stdin_file.read(&buffer) catch {
        // Return empty string on error
        const result: *RocStr = @ptrCast(@alignCast(ret_ptr));
        result.* = RocStr.empty();
        return;
    };

    // Handle EOF (no bytes read)
    if (bytes_read == 0) {
        const result: *RocStr = @ptrCast(@alignCast(ret_ptr));
        result.* = RocStr.empty();
        return;
    }

    // Find newline and trim it (handle both \n and \r\n)
    const line_with_newline = buffer[0..bytes_read];
    var line = if (std.mem.indexOfScalar(u8, line_with_newline, '\n')) |newline_idx|
        line_with_newline[0..newline_idx]
    else
        line_with_newline;

    // Also trim trailing \r for Windows line endings
    if (line.len > 0 and line[line.len - 1] == '\r') {
        line = line[0 .. line.len - 1];
    }

    // Allocate through Roc's allocation system to ensure proper size-tracking metadata
    var roc_alloc_args = builtins.host_abi.RocAlloc{
        .alignment = 1,
        .length = line.len,
        .answer = undefined,
    };
    ops.roc_alloc(&roc_alloc_args, ops.env);

    // Copy line data to the Roc-allocated memory
    const line_copy: [*]u8 = @ptrCast(roc_alloc_args.answer);
    @memcpy(line_copy[0..line.len], line);

    // Create RocStr from the read line and return it
    const result: *RocStr = @ptrCast(@alignCast(ret_ptr));
    result.* = RocStr.init(line_copy, line.len, ops);
}

/// Hosted function: Stdout.line! (index 2 - sorted alphabetically)
/// Follows RocCall ABI: (ops, ret_ptr, args_ptr)
/// Returns {} and takes Str as argument
fn hostedStdoutLine(ops: *builtins.host_abi.RocOps, ret_ptr: *anyopaque, args_ptr: *anyopaque) callconv(.c) void {
    _ = ops;
    _ = ret_ptr; // Return value is {} which is zero-sized

    // Arguments struct for single Str parameter
    const Args = extern struct { str: RocStr };
    const args: *Args = @ptrCast(@alignCast(args_ptr));

    const message = args.str.asSlice();
    const stdout: std.fs.File = .stdout();
    stdout.writeAll(message) catch {};
    stdout.writeAll("\n") catch {};
}

/// Array of hosted function pointers, sorted alphabetically by fully-qualified name
/// These correspond to the hosted functions defined in Stderr, Stdin, and Stdout Type Modules
const hosted_function_ptrs = [_]builtins.host_abi.HostedFn{
    hostedStderrLine, // Stderr.line! (index 0)
    hostedStdinLine, // Stdin.line! (index 1)
    hostedStdoutLine, // Stdout.line! (index 2)
};

/// Platform host entrypoint
fn platform_main(argc: usize, argv: [*][*:0]u8) c_int {
    var host_env = HostEnv{
        .leak_tracker = LeakTrackingAllocator.init(std.heap.page_allocator),
    };
    defer host_env.leak_tracker.deinit();

    // Create the RocOps struct
    var roc_ops = builtins.host_abi.RocOps{
        .env = @as(*anyopaque, @ptrCast(&host_env)),
        .roc_alloc = rocAllocFn,
        .roc_dealloc = rocDeallocFn,
        .roc_realloc = rocReallocFn,
        .roc_dbg = rocDbgFn,
        .roc_expect_failed = rocExpectFailedFn,
        .roc_crashed = rocCrashedFn,
        .hosted_fns = .{
            .count = hosted_function_ptrs.len,
            .fns = @constCast(&hosted_function_ptrs),
        },
    };

    // Build List(Str) from argc/argv
    std.log.debug("[HOST] Building args...", .{});
    const args_list = buildStrArgsList(argc, argv, &roc_ops);
    std.log.debug("[HOST] args_list ptr=0x{x} len={d}", .{ @intFromPtr(args_list.bytes), args_list.length });

    // Call the app's main! entrypoint - returns I32 exit code
    std.log.debug("[HOST] Calling roc__main_for_host...", .{});

    var exit_code: i32 = -99;
    roc__main_for_host(&roc_ops, @as(*anyopaque, @ptrCast(&exit_code)), @as(*anyopaque, @ptrCast(@constCast(&args_list))));

    std.log.debug("[HOST] Returned from roc, exit_code={d}", .{exit_code});

    // Check for memory leaks before returning
    if (host_env.leak_tracker.checkLeaks()) {
        std.process.exit(1);
    }

    return exit_code;
}

/// Build a RocList of RocStr from argc/argv
fn buildStrArgsList(argc: usize, argv: [*][*:0]u8, roc_ops: *builtins.host_abi.RocOps) RocList {
    if (argc == 0) {
        return RocList.empty();
    }

    // Allocate list with proper refcount header using RocList.allocateExact
    const args_list = RocList.allocateExact(
        @alignOf(RocStr),
        argc,
        @sizeOf(RocStr),
        true, // elements are refcounted (RocStr)
        roc_ops,
    );

    const args_ptr: [*]RocStr = @ptrCast(@alignCast(args_list.bytes));

    // Build each argument string
    for (0..argc) |i| {
        const arg_cstr = argv[i];
        const arg_len = std.mem.len(arg_cstr);

        // RocStr.init takes a const pointer to read FROM and allocates internally
        args_ptr[i] = RocStr.init(arg_cstr, arg_len, roc_ops);
    }

    return args_list;
}
