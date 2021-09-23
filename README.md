# struct_san - struct sanitizer
### 简介
`struct_san`是一个动态检测内核结构体函数指针的漏洞防御工具。业界对于结构体函数指针的保护主要集中在` Control-Flow Integrity (CFI)`,也就是关注在控制流上，没有关注在数据流上，例如某些`CFI`验证函数指针的方案是采用类型验证，如果指针被修改为同类型的函数则保护无效。启用`CFI`也需要对所有的代码进行插桩保护，造成很大的性能开销，
### 功能及使用

* 需求分析
  
`struct_san`的使用场景是保护在特定代码路径下的结构体函数不被修改。比如用在一些漏洞利用常常使用的代码路径上。以避免全面插桩带来不必要的性能开销。

* 使用方法

`struct_san`新增一个`GNU Attributes __attribute__ ((sanitize_struct)) `。
使用方法是在想要保护的结构体类型声明处和调用此结构体的函数指针的函数加入此关键字，

例如想要保护内核中的`pipe_buf_release()`代码中的`pipe_buf_operations->release()`函数。

1.在结构体类型声明时加入此关键字
```
struct __attribute__ ((sanitize_struct)) pipe_buf_operations {                                                                                                                                                                                               
    /*
     * ->confirm() verifies that the data in the pipe buffer is there
     * and that the contents are good. If the pages in the pipe belong
     * to a file system, we may need to wait for IO completion in this
     * hook. Returns 0 for good, or a negative error value in case of
     * error.  If not present all pages are considered good.                                                                                                                                                                                                 
     */
    int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);                                                                                                                                                                                          
  
    /*
     * When the contents of this pipe buffer has been completely
     * consumed by a reader, ->release() is called.                                                                                                                                                                                                          
     */                        
    void (*release)(struct pipe_inode_info *, struct pipe_buffer *);                                                                                                                                                                                         

    /*
     * Attempt to take ownership of the pipe buffer and its contents.
     * ->try_steal() returns %true for success, in which case the contents
     * of the pipe (the buf->page) is locked and now completely owned by the
     * caller. The page may then be transferred to a different mapping, the
     * most often used case is insertion into different file address space                                                                                                                                                                                   
     * cache.
     */
    bool (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *);                                                                                                                                                                                       

    /*
     * Get a reference to the pipe buffer.                                                                                                                                                                                                                   
     */
    bool (*get)(struct pipe_inode_info *, struct pipe_buffer *);                                                                                                                                                                                             
};

```
在类型声明完成以后，`struct_san`会将此类型的所有结构体实例保存到`.sanitize_struct`段内。

2.在`pipe_buf_release()`函数的声明和定义处加关键字，加入关键字后会在调用`pipe_buf_operations->release()`前插入校验函数`__sanitizer_struct_guard__()`

下面是插桩的前后对比
```
;; Function pipe_buf_release (pipe_buf_release, funcdef_no=3005, decl_uid=35109, cgraph_uid=3098, symbol_order=3148)

;; 
3 basic blocks, 2 edges, last basic block 3.

;; basic block 2, loop depth 0, count 1073741824 (estimated locally), maybe hot
;;  prev block 0, next block 1, flags: (NEW, VISITED)
;;  pred:       ENTRY [always]  count:1073741824 (estimated locally) (FALLTHRU,EXECUTABLE)
;;  succ:       EXIT [always]  count:1073741824 (estimated locally) (EXECUTABLE)

__attribute__((sanitize_struct, noinline))
pipe_buf_release (struct pipe_inode_info * pipe, struct pipe_buffer * buf)
{
  const struct pipe_buf_operations * ops;
  void (*<T257e>) (struct pipe_inode_info *, struct pipe_buffer *) _1;

;;   basic block 2, loop depth 0, count 1073741824 (estimated locally), maybe hot
;;    prev block 0, next block 1, flags: (NEW, VISITED)
;;    pred:       ENTRY [always]  count:1073741824 (estimated locally) (FALLTHRU,EXECUTABLE)
  # DEBUG BEGIN_STMT
  ops_4 = buf_3(D)->ops;
  # DEBUG ops => ops_4
  # DEBUG BEGIN_STMT
  buf_3(D)->ops = 0B;
  # DEBUG BEGIN_STMT
  _1 = ops_4->release;
  _1 (pipe_6(D), buf_3(D));
  return;
;;    succ:       EXIT [always]  count:1073741824 (estimated locally) (EXECUTABLE)

}
```
```
;; Function pipe_buf_release (pipe_buf_release, funcdef_no=3005, decl_uid=35109, cgraph_uid=3098, symbol_order=3148)

;; 
3 basic blocks, 2 edges, last basic block 3.

;; basic block 2, loop depth 0, count 1073741824 (estimated locally), maybe hot
;;  prev block 0, next block 1, flags: (NEW, VISITED)
;;  pred:       ENTRY [always]  count:1073741824 (estimated locally) (FALLTHRU,EXECUTABLE)
;;  succ:       EXIT [always]  count:1073741824 (estimated locally) (EXECUTABLE)

__attribute__((sanitize_struct, noinline))
pipe_buf_release (struct pipe_inode_info * pipe, struct pipe_buffer * buf)
{
  const struct pipe_buf_operations * ops;
  void (*<T257e>) (struct pipe_inode_info *, struct pipe_buffer *) _1;
  void (*<T257e>) (struct pipe_inode_info *, struct pipe_buffer *) STRUCT_I_8;

;;   basic block 2, loop depth 0, count 1073741824 (estimated locally), maybe hot
;;    prev block 0, next block 1, flags: (NEW, VISITED)
;;    pred:       ENTRY [always]  count:1073741824 (estimated locally) (FALLTHRU,EXECUTABLE)
  # DEBUG BEGIN_STMT
  ops_4 = buf_3(D)->ops;
  # DEBUG ops => ops_4
  # DEBUG BEGIN_STMT
  buf_3(D)->ops = 0B;
  # DEBUG BEGIN_STMT
  _1 = ops_4->release;
  STRUCT_I_8 = __sanitizer_struct_guard__ (&ops_4->release, _1);
  STRUCT_I_8 (pipe_6(D), buf_3(D));
  return;
;;    succ:       EXIT [always]  count:1073741824 (estimated locally) (EXECUTABLE)

}
```

### 算法
`struct_san`的算法是在内核中开辟一个`128M`大小shadow memory用来保存结构体和结构指针的对应关系。`__sanitizer_struct_guard__()`在调用时会检测传入的`struct`和函数指针是否在shadow memory中，如果不在则抛出一个`ud2异常`，否则返回函数指针。

### 效果
下面是对`CVE-2021-22555`漏洞的防御
```
test1@structsan:~$ ./exploit 
[+] Linux Privilege Escalation by theflow@ - 2021

[+] STAGE 0: Initialization
[*] Setting up namespace sandbox...
[*] Initializing sockets and message queues...

[+] STAGE 1: Memory corruption
[*] Spraying primary messages...
[*] Spraying secondary messages...
[*] Creating holes in primary messages...
[*] Triggering out-of-bounds write...
[   25.651883] x_tables: ip_tables: icmp.0 match: invalid size 8 (kernel) != (user) 3850
[*] Searching for corrupted primary message...
[+] fake_idx: bf9
[+] real_idx: be5

[+] STAGE 2: SMAP bypass
[*] Freeing real secondary message...
[*] Spraying fake secondary messages...
[*] Leaking adjacent secondary message...
[+] kheap_addr: ffff888111c0e000
[*] Freeing fake secondary messages...
[*] Spraying fake secondary messages...
[*] Leaking primary message...
[+] kheap_addr: ffff888112310000

[+] STAGE 3: KASLR bypass
[*] Freeing fake secondary messages...
[*] Spraying fake secondary messages...
[*] Freeing sk_buff data buffer...
[*] Spraying pipe_buffer objects...
[*] Leaking and freeing pipe_buffer object...
[+] anon_pipe_buf_ops: ffffffff82b70d60
[+] kbase_addr: ffffffff81000000

[+] STAGE 4: Kernel code execution
[*] Spraying fake pipe_buffer objects...
[*] Releasing pipe_buffer objects...
[   25.709459] invalid opcode: 0000 [#1] SMP NOPTI
[   25.709842] CPU: 0 PID: 306 Comm: exploit Tainted: G            E     5.12.0-rc4+ #34
[   25.710004] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   25.710004] RIP: 0010:__sanitizer_struct_guard__+0x22/0x30
[   25.710004] Code: cc cc cc cc cc cc cc cc 66 66 66 66 90 55 48 31 f7 48 8b 15 40 c8 e0 01 48 89 f0 81 e7 ff ff ff 07 80 3c 3a 00 48 89 e5 75 02 <0f> 0b 5d c3 66 2e 0f 1f 84 00 00 00 00 00 66 66 66 66 90 55 bf 00
[   25.710004] RSP: 0018:ffffc9000826bde0 EFLAGS: 00000246
[   25.710004] RAX: ffffffff816e9783 RBX: 0000000000000000 RCX: 0000000000000000
[   25.710004] RDX: ffffc90000010000 RSI: ffffffff816e9783 RDI: 00000000035f951b
[   25.710004] RBP: ffffc9000826bde0 R08: 0000000000000000 R09: ffff88810d0131e0
[   25.710004] R10: 0000000000000008 R11: ffff88810b42bd10 R12: ffff888112310000
[   25.710004] R13: ffff88810fa1f600 R14: ffff88810d013268 R15: ffff8881095fcb40
[   25.710004] FS:  0000000000000000(0000) GS:ffff88813bc00000(0063) knlGS:000000000854b840
[   25.710004] CS:  0010 DS: 002b ES: 002b CR0: 0000000080050033
[   25.710004] CR2: 00000000080e2000 CR3: 000000010c9ce000 CR4: 00000000000006f0
[   25.710004] Call Trace:
[   25.710004]  pipe_buf_release+0x2c/0x40
[   25.710004]  free_pipe_info+0x7d/0xc0
[   25.710004]  pipe_release+0x114/0x120
[   25.710004]  __fput+0x9f/0x250
[   25.710004]  ____fput+0xe/0x10
[   25.710004]  task_work_run+0x6d/0xa0
[   25.710004]  exit_to_user_mode_prepare+0x18d/0x190
[   25.710004]  syscall_exit_to_user_mode+0x27/0x50
[   25.710004]  ? __ia32_sys_close+0x12/0x40
[   25.710004]  __do_fast_syscall_32+0x72/0xa0
[   25.710004]  do_fast_syscall_32+0x34/0x80
[   25.710004]  entry_SYSCALL_compat_after_hwframe+0x45/0x4d
[   25.710004] RIP: 0023:0xf7f67549
[   25.710004] Code: b8 01 10 06 03 74 b4 01 10 07 03 74 b0 01 10 08 03 74 d8 01 00 00 00 00 00 00 00 00 00 00 00 00 00 51 52 55 89 cd 0f 05 cd 80 <5d> 5a 59 c3 90 90 90 90 8d b4 26 00 00 00 00 8d b4 26 00 00 00 00
[   25.710004] RSP: 002b:00000000ffc43280 EFLAGS: 00000246 ORIG_RAX: 0000000000000006
[   25.710004] RAX: 0000000000000000 RBX: 000000000000000d RCX: 00000000ffffffff
[   25.710004] RDX: 00000000080e0870 RSI: 0000000000000000 RDI: 0000000000000000
[   25.710004] RBP: 00000000ffc48d48 R08: 0000000000000000 R09: 0000000000000000
[   25.710004] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
[   25.710004] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   25.710004] Modules linked in: xt_NFQUEUE(E) bpfilter(E) ppdev(E) kvm_amd(E) ccp(E) kvm(E) bochs_drm(E) drm_vram_helper(E) drm_ttm_helper(E) ttm(E) snd_pcm(E) drm_kms_helper(E) cec(E) rc_core(E) snd_timer(E) snd(E) input_leds(E) soundcore(E) drm(E) psmouse(E) parport_pc(E) pcspkr(E) serio_raw(E) fb_sys_fops(E) parport(E) syscopyarea(E) sysfillrect(E) sysimgblt(E) i2c_piix4(E) pata_acpi(E) floppy(E) qemu_fw_cfg(E) evbug(E) mac_hid(E) binfmt_misc(E) ip_tables(E) autofs4(E)
[   25.724735] ---[ end trace 4634599e7a9af45d ]---
[   25.725272] RIP: 0010:__sanitizer_struct_guard__+0x22/0x30
[   25.725869] Code: cc cc cc cc cc cc cc cc 66 66 66 66 90 55 48 31 f7 48 8b 15 40 c8 e0 01 48 89 f0 81 e7 ff ff ff 07 80 3c 3a 00 48 89 e5 75 02 <0f> 0b 5d c3 66 2e 0f 1f 84 00 00 00 00 00 66 66 66 66 90 55 bf 00
[   25.727870] RSP: 0018:ffffc9000826bde0 EFLAGS: 00000246
[   25.728384] RAX: ffffffff816e9783 RBX: 0000000000000000 RCX: 0000000000000000
[   25.729034] RDX: ffffc90000010000 RSI: ffffffff816e9783 RDI: 00000000035f951b
[   25.729633] RBP: ffffc9000826bde0 R08: 0000000000000000 R09: ffff88810d0131e0
[   25.730402] R10: 0000000000000008 R11: ffff88810b42bd10 R12: ffff888112310000
[   25.730903] R13: ffff88810fa1f600 R14: ffff88810d013268 R15: ffff8881095fcb40
[   25.731420] FS:  0000000000000000(0000) GS:ffff88813bc00000(0063) knlGS:000000000854b840
[   25.732296] CS:  0010 DS: 002b ES: 002b CR0: 0000000080050033
[   25.732679] CR2: 00000000080e2000 CR3: 000000010c9ce000 CR4: 00000000000006f0
Segmentation fault
test1@structsan:~$ 

```
