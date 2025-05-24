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

struct key_definition {
    const char *keyname;
    unsigned char scancode;
};

/* This table is based on the layout of my laptop.
 * Don't assume this is the  universal scancodes.
 */
static const struct key_definition key_table[] = {
    {"esc", 1},        {"f1", 59},
    {"f2", 60},        {"f3", 61},
    {"f4", 62},        {"f5", 63},
    {"f6", 64},        {"f7", 65},
    {"f8", 66},        {"f9", 67},
    {"f10", 68},       {"f11", 87},
    {"f12", 88},       {"zenhan", 41},
    {"1", 2},          {"2", 3},
    {"3", 4},          {"4", 5},
    {"5", 6},          {"6", 7},
    {"7", 8},          {"8", 9},
    {"9", 10},         {"0", 11},
    {"-", 12},         {"^", 13},
    {"yen", 125},      {"backspace", 14},
    {"tab", 15},       {"q", 16},
    {"w", 17},         {"e", 18},
    {"r", 19},         {"t", 20},
    {"y", 21},         {"u", 22},
    {"i", 23},         {"o", 24},
    {"p", 25},         {"@", 26},
    {"[", 27},         {"capslock", 58},
    {"a", 30},         {"s", 31},
    {"d", 32},         {"f", 33},
    {"g", 34},         {"h", 35},
    {"j", 36},         {"k", 37},
    {"l", 38},         {";", 39},
    {"colon", 40},     {"]", 43},
    {"enter", 28},     {"leftshift", 42},
    {"z", 44},         {"x", 45},
    {"c", 46},         {"v", 47},
    {"b", 48},         {"n", 49},
    {"m", 50},         {",", 51},
    {".", 52},         {"/", 53},
    {"\\", 115},       {"rightshift", 54},
    {"leftctrl", 29},  {"leftalt", 56},
    {"muhenkan", 123}, {"space", 57},
    {"henkan", 121},   {"katakanahiragana", 112},
};

static int validate_key_table(void) {
    int error_count = 0;

    for (int i = 0; i < ARRAY_SIZE(key_table); i++) {
        if (key_table[i].scancode >= SCANCODE_MAP_SIZE) {
            pr_err(
                "key_table[%d]: scancode %d out of range [0..%d)\n",
                i, key_table[i].scancode, SCANCODE_MAP_SIZE);
            error_count++;
        }

        if (!key_table[i].keyname || strlen(key_table[i].keyname) == 0) {
            pr_err("key_table[%d]: invalid keyname\n", i);
            error_count++;
        }
    }

    if (error_count > 0) {
        pr_err("Found %d errors in key_table. Module load aborted\n", error_count);
        return -EINVAL;
    }

    return 0;
}

static int find_scancode_by_keyname(char *keyname) {
    for (int i = 0; i < ARRAY_SIZE(key_table); i++) {
        if (strcasecmp(key_table[i].keyname, keyname) == 0) {
            return key_table[i].scancode;
        }
    }
    return -1;
}

struct parsed_key_mapping {
    char *src_str;
    char *dest_str;
    unsigned char src_scancode;
    unsigned char dest_scancode;
};

static int parse_scancode(char *token, struct parsed_key_mapping *key) {
    int ret;

    key->src_str = strsep(&token, ":");
    key->dest_str = token;
    if (!key->src_str || !key->dest_str) {
        pr_err("Invalid format. Expected 'src:dest'\n");
        return -EINVAL;
    }

    ret = find_scancode_by_keyname(key->src_str);
    if (ret < 0) {
        pr_err("Keyname %s not found.\n", key->src_str);
        return -EINVAL;
    }
    key->src_scancode = ret;

    ret = find_scancode_by_keyname(key->dest_str);
    if (ret < 0) {
        pr_err("Keyname %s not found.\n", key->dest_str);
        return -EINVAL;
    }
    key->dest_scancode = ret;

    return 0;
}

static const char *scancode_to_keyname[SCANCODE_MAP_SIZE];

static void init_scancode_to_keyname(void) {
    for (int i = 0; i < SCANCODE_MAP_SIZE; i++) {
        scancode_to_keyname[i] = NULL;
    }

    for (int i = 0; i < ARRAY_SIZE(key_table); i++) {
        scancode_to_keyname[key_table[i].scancode] = key_table[i].keyname;
    }
}

static int register_remap(char *token) {
    int ret, success_count = 0;
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
        struct parsed_key_mapping key;
        ret = parse_scancode(pair, &key);
        if (ret) {
            pr_warn("Skipping invalid mapping: %s\n", pair);
            continue;
        }

        new_scancode_map[key.src_scancode] = key.dest_scancode;
        pr_info("Remapped key %s to %s.\n", key.src_str, key.dest_str);
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
    if (size > 0 && kbuf[size-1] == '\n')
        kbuf[size-1] = '\0';

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

        const char *src_keyname = scancode_to_keyname[i];
        const char *dest_keyname = scancode_to_keyname[snapshot[i]];
        if (src_keyname && dest_keyname)
            seq_printf(seq, "%s:%s\n", src_keyname, dest_keyname);
        else
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

    ret = validate_key_table();
    if (ret < 0)
        return ret;

    init_scancode_to_keyname();

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
