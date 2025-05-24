# kmap

A Linux kernel module for remapping keyboard scan codes.

## Overview

kmap allows you to customize your keyboard layout by remapping scan codes directly in the Linux kernel. This works at a low level, providing an effective solution for:

- Swapping keys (e.g., CapsLock and Ctrl)
- Fixing broken keyboard keys
- Creating custom keyboard layouts

## Installation

### Prerequisites

- Linux kernel headers
- Build tools (make, gcc)

### Building and Loading

```sh
make
sudo insmod kmap.ko
```

To load with default mappings:

```sh
sudo insmod kmap.ko default_map="capslock:leftctrl,leftctrl:capslock,zenhan:esc"
```

## Usage

List current mappings:
```sh
cat /sys/kernel/debug/kmap/control
```

Set mappings (format is `scancode_src:scancode_dest,...`):

### Swap CapsLock (58) and Left Ctrl (29)
```sh
echo "capslock:leftctrl,leftctrl:capslock" > /sys/kernel/debug/kmap/control
```

Reset keys to default:

```sh
echo "capslock:capslock,leftctrl:leftctrl" > /sys/kernel/debug/kmap/control
```

For available keynames, please look at `key_table` in kmap.c.

## How It Works

kmap uses a kprobe to intercept keyboard scan codes at the `atkbd_receive_byte` function. The module maintains a mapping table and provides a debugfs interface at `/sys/kernel/debug/kmap/control`.

You can customize the hook point by modifying the `SYMBOL_NAME` define in the source code. This allows you to adapt kmap to different keyboard drivers or input subsystems, such as `serio_interrupt()` for broader device support, as long as the position of the argument is preserved.
