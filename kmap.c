#define pr_fmt(fmt) "%s:%s():%d: " fmt, KBUILD_MODNAME, __func__, __LINE__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/input.h>
#include <linux/debugfs.h>

#define KBD_STATUS_MASK 0x80
#define KBD_SCANCODE_MASK 0x7f

/* Which function to choose as the attach point:
 * Since builtin keyboard is probed by atkbd in my laptop like this:
 *     $ ls -l /sys/devices/platform/i8042/serio0/driver
 *     lrwxrwxrwx 1 root root 0 May 15 22:11 /sys/devices/platform/i8042/serio0/driver -> ../../../../bus/serio/drivers/atkbd
 * functions of atkbd driver are good candidates to attach the kprobe. Also we
 * can choose functions around i8042 and serio subsystem, as far as they have
 * scancode/keycode as their argument, such as serio_interrupt(). In this case,
 * of course, this kprobe has impacts to all devices that use those subsystem,
 * not only to atkbd.
 */
#define SYMBOL_NAME "atkbd_receive_byte"
#define SCANCODE_MAP_SIZE 128

static char *default_map = NULL;
module_param(default_map, charp, 0444);
MODULE_PARM_DESC(default_map,
                 "Default key mappings in format 'src1:dest1,src2:dest2,...'");

static unsigned char __rcu *scancode_map_ptr = NULL;

static struct dentry *debugfs_dir;
static struct dentry *debugfs_control;

static int __kprobes swap_scancode(struct kprobe *p, struct pt_regs *regs) {
    /* rsi is second argument in x86. */
    unsigned char scancode = regs->si & KBD_SCANCODE_MASK;
    unsigned char status = regs->si & KBD_STATUS_MASK;

    rcu_read_lock();
    regs->si = rcu_dereference(scancode_map_ptr)[scancode] + status;
    rcu_read_unlock();

    return 0;
}

static struct kprobe kp = {
    .symbol_name = SYMBOL_NAME,
    .pre_handler = swap_scancode,
};

static int parse_scancode(char *token, unsigned long *src,
                          unsigned long *dest) {
    int ret;
    char *src_str, *dest_str;

    src_str = strsep(&token, ":");
    dest_str = token;
    if (!src_str || !dest_str) {
        pr_err("Invalid format. Expected 'src:dest'\n");
        return -EINVAL;
    }

    ret = kstrtoul(src_str, 0, src);
    if (ret) {
        pr_err("Invalid src value: %s\n", src_str);
        return ret;
    }

    ret = kstrtoul(dest_str, 0, dest);
    if (ret) {
        pr_err("Invalid dest value: %s\n", dest_str);
        return ret;
    }

    if (*src >= SCANCODE_MAP_SIZE || *dest >= SCANCODE_MAP_SIZE) {
        pr_err("Scan code must be in range 0-%d. Got src=%lu, dest=%lu\n",
               SCANCODE_MAP_SIZE - 1, *src, *dest);
        return -EINVAL;
    }

    return 0;
}

static int register_remap(char *token) {
    int ret, success_count = 0;
    unsigned long src, dest;
    unsigned char *new_scancode_map = NULL;
    unsigned char *old_scancode_map;
    char *pair, *rest;

    new_scancode_map = kmalloc(SCANCODE_MAP_SIZE, GFP_KERNEL);
    if (!new_scancode_map) {
        pr_err("Failed to allocate memory for new_scancode_map. Abort updating "
               "scancode_map\n");
        return -ENOMEM;
    }

    rcu_read_lock();
    old_scancode_map = rcu_dereference(scancode_map_ptr);
    memcpy(new_scancode_map, old_scancode_map, SCANCODE_MAP_SIZE);
    rcu_read_unlock();

    rest = token;
    while ((pair = strsep(&rest, ",")) != NULL) {
        ret = parse_scancode(pair, &src, &dest);
        if (ret) {
            pr_warn("Skipping invalid mapping: %s\n", pair);
            continue;
        }

        new_scancode_map[src] = dest;
        pr_info("Remapped key %lu to %lu.\n", src, dest);
        success_count++;
    }

    if (success_count == 0) {
        kfree(new_scancode_map);
        return -EINVAL;
    }

    rcu_assign_pointer(scancode_map_ptr, new_scancode_map);
    synchronize_rcu();
    kfree(old_scancode_map);

    return 0; 
}

/* assume "src1:dest1,src2:dest2,..." format */
static ssize_t debugfs_write(struct file *file, const char __user *buf,
                             size_t size, loff_t *ppos) {
    int ret = 0;
    char *kbuf;

    kbuf = kmalloc(size + 1, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    if (copy_from_user(kbuf, buf, size)) {
        ret = -EFAULT;
        goto free;
    }

    kbuf[size] = '\0';

    ret = register_remap(kbuf);
    if (ret) {
        goto free;
    }

    *ppos += size;
    ret = size;

free:
    kfree(kbuf);
    return ret;
}

static int kmap_seq_show(struct seq_file *seq, void *v) {
    unsigned char snapshot[SCANCODE_MAP_SIZE];
    unsigned char *map;

    rcu_read_lock();
    map = rcu_dereference(scancode_map_ptr);
    memcpy(snapshot, map, SCANCODE_MAP_SIZE);
    rcu_read_unlock();

    // map might be stale, but it's okay.
    for (int i = 0; i < SCANCODE_MAP_SIZE; i++) {
        if (i == snapshot[i])
            continue;
        seq_printf(seq, "%d:%d\n", i, snapshot[i]);
    }

    return 0;
}

static int kmap_open(struct inode *inode, struct file *file) {
    return single_open(file, kmap_seq_show, NULL);
}

static struct file_operations debugfs_fops = {
    .owner = THIS_MODULE,
    .open = kmap_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
    .write = debugfs_write,
};

static int init_scancode_map(void) {
    unsigned char *initial_map;
    char *default_map_copy = NULL;

    initial_map = kmalloc(SCANCODE_MAP_SIZE, GFP_KERNEL);
    if (!initial_map) {
        pr_err("Failed to allocate memory for initial_map.\n");
        return -ENOMEM;
    }

    for (int i = 0; i < SCANCODE_MAP_SIZE; i++)
        initial_map[i] = i;

    rcu_assign_pointer(scancode_map_ptr, initial_map);

    if (default_map) {
        default_map_copy = kstrdup(default_map, GFP_KERNEL);
        if (!default_map_copy) {
            pr_warn("Failed to allocate memory for default_map copy. Skip "
                    "applying default_map.\n");
            return 0;
        }
        // Don't return error even if register_remap returns -EINVAL
        register_remap(default_map_copy);
        kfree(default_map_copy);
    }

    return 0;
}

static void init_debugfs(void) {
    debugfs_dir = debugfs_create_dir("kmap", NULL);
    debugfs_control = debugfs_create_file("control", S_IWUSR | S_IRUGO,
                                          debugfs_dir, NULL, &debugfs_fops);
    if (IS_ERR(debugfs_dir) || IS_ERR(debugfs_control))
        pr_warn("debugfs interface unavailable. Use `default_map` module "
                "parameter for static configuration.\n "
                "The parameter is read-only, so if you want to change the "
                "default mapping, please unload once and reload with the "
                "parameter.\n");
}

static int kmap_init(void) {
    int ret = 0;

    ret = init_scancode_map();
    if (ret) {
        pr_err("Failed to initialize scancode_map\n");
        return ret;
    }

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("register_kprobe failed, returned %d\n", ret);
        goto free;
    }

    init_debugfs();

    pr_info("kmap loaded at %s.\n", SYMBOL_NAME);
    return 0;

free:
    synchronize_rcu();
    kfree(rcu_dereference_protected(scancode_map_ptr, 1));
    return ret;
}

static void kmap_exit(void) {
    debugfs_remove_recursive(debugfs_dir);
    unregister_kprobe(&kp);

    synchronize_rcu();
    kfree(rcu_dereference_protected(scancode_map_ptr, 1));
    pr_info("kmap unloaded.\n");
    return;
}

module_init(kmap_init);
module_exit(kmap_exit);
MODULE_LICENSE("GPL");
