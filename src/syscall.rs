use core::arch::asm;

#[inline(never)]
pub unsafe fn syscall3(number: u32, arg1: u64, arg2: u64, arg3: u64) -> u64 {
	let output: u64;
	asm!(
		"syscall",
		in("rax") number,
		in("r10") arg1,
		in("rdx") arg2,
		in("r8") arg3,
		lateout("rax") output,
		lateout("rcx") _,
		lateout("r11") _
	);
	output
}

#[inline(never)]
pub unsafe fn syscall5(number: u32, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
	let output: u64;
	asm!(
		"sub rsp, 0x38",
		"mov [rsp+0x28], {arg5}",
		"syscall",
		"add rsp, 0x38",
		arg5 = in(reg) arg5,
		in("rax") number,
		in("r10") arg1,
		in("rdx") arg2,
		in("r8") arg3,
		in("r9") arg4,
		lateout("rax") output,
		lateout("rcx") _,
		lateout("r11") _
	);
	output
}

#[inline(never)]
pub unsafe fn syscall6(
	number: u32,
	arg1: u64,
	arg2: u64,
	arg3: u64,
	arg4: u64,
	arg5: u64,
	arg6: u64,
) -> u64 {
	let output: u64;
	asm!(
		"sub rsp, 0x38",
		"mov [rsp+0x30], {arg6}",
		"mov [rsp+0x28], {arg5}",
		"syscall",
		"add rsp, 0x38",
		arg5 = in(reg) arg5,
		arg6 = in(reg) arg6,
		in("rax") number,
		in("r10") arg1,
		in("rdx") arg2,
		in("r8") arg3,
		in("r9") arg4,
		lateout("rax") output,
		lateout("rcx") _,
		lateout("r11") _
	);
	output
}
