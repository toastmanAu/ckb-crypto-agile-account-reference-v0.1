/* CKB-VM W^X-safe two-segment linker layout. */
ENTRY(_start)

SECTIONS {
    . = 0x10000;

    .text : {
        *(.text.startup)
        *(.text*)
    }

    . = ALIGN(0x1000);
    .rodata : ALIGN(0x1000) {
        *(.rodata*)
        *(.srodata*)
    }

    . = ALIGN(0x1000);
    .sdata : {
        __global_pointer$ = . + 0x800;
        *(.sdata*)
    }
    .data : ALIGN(8) {
        *(.data*)
    }
    .sbss : ALIGN(8) {
        *(.sbss*)
    }
    .bss : ALIGN(8) {
        *(.bss*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note*)
        *(.comment*)
        *(.riscv.attributes*)
    }
}
