cmd_/root/Kkit/example/modexec.ko := ld -r -m elf_x86_64  -z max-page-size=0x200000 -z noexecstack   --build-id  -T ./scripts/module-common.lds -o /root/Kkit/example/modexec.ko /root/Kkit/example/modexec.o /root/Kkit/example/modexec.mod.o;  true