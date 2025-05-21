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

static DEFINE_SPINLOCK(scancode_map_lock);
static unsigned char scancode_map[SCANCODE_MAP_SIZE];

static struct dentry *debugfs_dir;
static struct dentry *debugfs_control;

static int __kprobes swap_scancode(struct kprobe *p, struct pt_regs *regs) {
    /* rsi is second argument in x86. */
    unsigned char scancode = regs->si & KBD_SCANCODE_MASK;
    unsigned char status = regs->si & KBD_STATUS_MASK;

    spin_lock(&scancode_map_lock);
    regs->si = scancode_map[scancode] + status;
    spin_unlock(&scancode_map_lock);
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
    unsigned long flags;
    unsigned long src, dest;
    char *pair, *rest;

    rest = token;

    while ((pair = strsep(&rest, ",")) != NULL) {
        ret = parse_scancode(pair, &src, &dest);
        if (ret) {
            pr_warn("Skipping invalid mapping: %s\n", pair);
            continue;
        }

        spin_lock_irqsave(&scancode_map_lock, flags);
        scancode_map[src] = dest;
        spin_unlock_irqrestore(&scancode_map_lock, flags);

        pr_info("Remapped key %lu to %lu.\n", src, dest);
        success_count++;
    }

    return success_count > 0 ? 0 : -EINVAL;
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
    unsigned char val;

    // each items in map might be stale, but it's okay.
    for (int i = 0; i < SCANCODE_MAP_SIZE; i++) {
        val = READ_ONCE(scancode_map[i]);
        if (i == val)
            continue;
        seq_printf(seq, "%d:%d\n", i, val);
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

static void init_scancode_map(void) {
    char *default_map_copy = NULL;

    for (int i = 0; i < SCANCODE_MAP_SIZE; i++)
        scancode_map[i] = i;

    if (default_map) {
        default_map_copy = kstrdup(default_map, GFP_KERNEL);
        if (!default_map_copy) {
            pr_warn("Failed to allocate memory for default_map copy. Skip "
                    "applying default_map.");
            return;
        }
        // Don't return error even if register_remap returns -EINVAL
        register_remap(default_map_copy);
        kfree(default_map_copy);
    }
}

static int kmap_init(void) {
    int ret = 0;

    init_scancode_map();

    /* debugfs */
    debugfs_dir = debugfs_create_dir("kmap", NULL);
    if (!debugfs_dir) {
        pr_err("failed to create debugfs dir\n");
        return PTR_ERR(debugfs_dir);
    }

    debugfs_control = debugfs_create_file("control", S_IWUSR | S_IRUGO,
                                          debugfs_dir, NULL, &debugfs_fops);
    if (!debugfs_control) {
        pr_err("failed to create debugfs file\n");
        ret = PTR_ERR(debugfs_control);
        goto free_debugfs_dir;
    }

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("register_kprobe failed, returned %d\n", ret);
        goto free_debugfs_dir;
    }

    pr_info("kmap loaded at %s.\n", SYMBOL_NAME);
    return 0;

free_debugfs_dir:
    debugfs_remove_recursive(debugfs_dir);
    return ret;
}

static void kmap_exit(void) {
    debugfs_remove_recursive(debugfs_dir);
    unregister_kprobe(&kp);
    pr_info("kmap unloaded.\n");
    return;
}

module_init(kmap_init);
module_exit(kmap_exit);
MODULE_LICENSE("GPL");
