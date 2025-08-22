/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2019-2023 checkra1n team
 *
 * This file is part of pongoOS.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
#include "libc_workarounds.h"
#include <stdbool.h>
#include <stdint.h>
#include <pongo.h>

extern _Noreturn void jump_to_image(uint64_t image, uint64_t args, uint64_t tramp);
extern _Noreturn void setup_el1(uint64_t, uint64_t, void * entryp);
extern _Noreturn void main(void* boot_image, void* boot_args);

//volatile void d$demote_patch(void * image);

void iorvbar_yeet(volatile void *boot_image) __asm__("iorvbar_yeet");
void aes_keygen(volatile void *boot_image) __asm__("aes_keygen");
void recfg_yoink(volatile void *boot_image) __asm__("recfg_yoink");
void fuse_jump(volatile void *boot_image) __asm__("fuse_jump");
void antitrust(volatile void *boot_image) __asm__("antitrust");

extern uint8_t need_to_release_L3_SRAM;
extern uint64_t ipf_flag;

// A value large enough to encompass the iBoot TEXT section,
// but small enough to not include the embedded firmware blobs.
// NOTE: Independent definition exists in stage2.
#define SAFE_TEXT_SIZE 0x7ff00

asm(".text\n"
    ".align 2\n"
    ".globl _patchfind_forward\n"
    "_patchfind_forward:\n"
    "ldr        w4, [x0]\n"
    "and        w4, w4, w2\n"
    "cmp        w4, w1\n"
    "b.eq       1f\n"
    "add        x0, x0, #0x4\n"
    "sub        w3, w3, #0x4\n"
    "cbnz       w3, _patchfind_forward\n"
    "mov        x0, xzr\n"
    "1:\n"
    "ret\n"
    );

asm(".text\n"
    ".align 2\n"
    ".globl _patchfind_backwards\n"
    "_patchfind_backwards:\n"
    "ldr        w4, [x0]\n"
    "and        w4, w4, w2\n"
    "cmp        w4, w1\n"
    "b.eq       1f\n"
    "sub        x0, x0, #0x4\n"
    "sub        w3, w3, #0x4\n"
    "cbnz       w3, _patchfind_backwards\n"
    "mov        x0, xzr\n"
    "1:\n"
    "ret\n"
    );

extern volatile uint32_t* patchfind_forward(volatile uint32_t* src, uint32_t match, uint32_t mask, uint32_t sz);
extern volatile uint32_t* patchfind_backwards(volatile uint32_t* src, uint32_t match, uint32_t mask, uint32_t sz);

// pacth image4_validate_property_callback
int sigcheck(volatile void *boot_image)
{
    volatile uint32_t* cur = (volatile uint32_t*)boot_image;
    
    // search 'DGST' (image4 payload digest) tag
    // These should fall into either "case 1" or "case 2".
    volatile uint32_t* dgst = NULL;
    
    // case 1, iOS 11.3 or later iBoot image, the following sequence of instruction set is found exactly once:
    // 00000001800c6a68     mov   w8, #0x5354           <- find this
    // 00000001800c6a6c     movk  w8, #0x4447, lsl #16
    // 00000001800c6a70     cmp   w20, w8
    // 00000001800c6a74     b.eq  loc_1800c6b40
    volatile uint32_t* mov_w8_1 = patchfind_forward(cur, 0x528a6a88, 0xffffffff, 0x7ff00); // mov w8, #0x5354
    if (mov_w8_1) {
        // check that the next instruction is what we expect
        if (mov_w8_1[1] != 0x72a888e8) { // movk w8, #0x4447, lsl #16
            return 1;
        }
        dgst = mov_w8_1;
    }
    
    // case 2, for iOS 9.0 through 11.2.6 instead contain the following sequence of instruction set found exactly once:
    // 00000001800c1318     mov   w8, #0x44470000       <- find this
    // 00000001800c131c     movk  w8, #0x5354
    // 00000001800c1320     cmp   w20, w8
    // 00000001800c1324     b.eq  loc_1800c138c         <- b.eq or b.ne
    if (!dgst) {
        cur = (volatile uint32_t*)boot_image;
        volatile uint32_t* mov_w8_2 = patchfind_forward(cur, 0x52a888e8, 0xffffffff, 0x7ff00); // mov w8, #0x44470000
        if (mov_w8_2) {
            // check that the next instruction is what we expect
            if (mov_w8_2[1] != 0x728a6a88) { // movk  w8, #0x5354
                return 2;
            }
            dgst = mov_w8_2;
        }
    }
    
    // case 3, we have iOS 8, so... it is so annoying
    // 000000087a18fe74         mov        w9, #0x44470000
    // 000000087a18fe78         movk       w9, #0x5354
    // 000000087a18fe7c         cmp        w20, w9
    // 000000087a18fe80         b.ne       loc_87a1901b8
    if (!dgst) {
        cur = (volatile uint32_t*)boot_image;
        volatile uint32_t* mov_w9 = patchfind_forward(cur, 0x52a888e9, 0xffffffff, 0x7ff00); // mov w9, #0x44470000
        if (mov_w9) {
            // check that the next instruction is what we expect
            if (mov_w9[1] != 0x728a6a89) { // movk  w9, #0x5354
                return 2;
            }
            dgst = mov_w9;
        }
    }
    
    if (!dgst) {
        return 4;
    }
    
    // Next we need to find the end point of this function.
    // However, some iBoots have "RET" after a branch instruction.
    // So we search for the previous stack frame instead of RET.
    // - example from A9 iOS 15 - 16 iBoot:
    // 000000018038ffec         ldp        fp, lr, [sp, #0x70]      <---+-- find this
    // 000000018038fff0         ldp        x20, x19, [sp, #0x60]        |
    // 000000018038fff4         ldp        x22, x21, [sp, #0x50]        |
    // 000000018038fff8         ldp        x24, x23, [sp, #0x40]    <---+
    // 000000018038fffc         b          loc_1803911b8
    // 00000001803911b8         add        sp, sp, #0x80
    // 00000001803911bc         ret
    bool found = 0;
    volatile uint32_t* frame = dgst;
    for (int i = 0; i < 2000; i++) {
        if ((frame[i + 0] & 0xffc07fff) == 0xa9407bfd && // ldp fp, lr, [sp, #X]
            (frame[i + 1] & 0xffc043f0) == 0xa94043f0 && // ldp x{16-31}, x{16-31}, [sp, #X]
            (frame[i + 2] & 0xffc043f0) == 0xa94043f0 && // ldp x{16-31}, x{16-31}, [sp, #X]
            (frame[i + 3] & 0xffc043f0) == 0xa94043f0) { // ldp x{16-31}, x{16-31}, [sp, #X]
            frame = &frame[i];
            found = 1;
            break;
        }
    }
    
    if (!found) {
        frame = dgst;
        for (int i = 0; i < 2000; i++) {
            if ((frame[i + 0] & 0xffc07fff) == 0xa9407bfd && // ldp fp, lr, [sp, #X]
                (frame[i + 1] & 0xffc043f0) == 0xa94043f0 && // ldp x{16-31}, x{16-31}, [sp, #X]
                (frame[i + 2] & 0xffc043f0) == 0xa94043f0 && // ldp x{16-31}, x{16-31}, [sp, #X]
                (frame[i + 3] & 0xffc003e0) == 0xa8c003e0) { // 
                frame = &frame[i];
                found = 1;
                break;
            }
        }
    }
    
    if (!found) {
        return 5;
    }
    
    // Finally, we need to patch this function so that it always returns 0.
    // If there is an instruction like mov x0, xN immediately before it, simply replace it with mov x0, #0.
    // - example from A10 iOS 11.3 - 18.4 iBoot
    // 00000001800c6f6c     mov   x0, x20               <- patch this
    // 00000001800c6f70     ldp   fp, lr, [sp, #0xa0]   <- we found this
    // 00000001800c6f74     ldp   x20, x19, [sp, #0x90]
    // 00000001800c6f78     ldp   x22, x21, [sp, #0x80]
    // 00000001800c6f7c     ldp   x24, x23, [sp, #0x70]
    // 00000001800c6f80     ldp   x26, x25, [sp, #0x60]
    // 00000001800c6f84     add   sp, sp, #0xb0
    // 00000001800c6f88     ret
    if ((frame[-1] & 0xfff0ffff) == 0xaa1003e0) { // mov x0, x{16-31}
        frame[-1] = 0xd2800000; // mov x0, #0
        return 0;
    }
    
    // It seems that if the immediately preceding instruction isn't a mov instruction,
    // it has a cbnz within a few instructions before it instead.
    // We can replace the cbnz instruction with mov x0, #0 and patch out the branch, patching it to always returns 0.
    // - example from A9 iOS 9 iBoot
    // 000000018038f410     cbnz       x8, loc_18038f49c    <- patch this
    // 000000018038f414     sub        sp, fp, #0x40
    // 000000018038f418     ldp        fp, lr, [sp, #0x40]  <- we found this
    // 000000018038f41c     ldp        x20, x19, [sp, #0x30]
    // 000000018038f420     ldp        x22, x21, [sp, #0x20]
    // 000000018038f424     ldp        x24, x23, [sp, #0x10]
    // 000000018038f428     ldp        x26, x25, [sp], #0x50
    // 000000018038f42c     ret
    volatile uint32_t* cbnz = patchfind_backwards(frame, 0xb5000000, 0xff000000, 0x10);
    if (cbnz) {
        *cbnz = 0xd2800000; // mov x0, #0
        return 0;
    }
    
    // Some iBoot images have b.ne instruction instead of cbnz xN
    // This is expected to be just before the RET gadget like cbnz.
    // - example from A9 iOS 13 iBoot
    // 00000001803901dc     cmp        x9, x8
    // 00000001803901e0     b.ne       loc_180390228        <- patch this
    // 00000001803901e4     ldp        fp, lr, [sp, #0x80]  <- we found this
    // 00000001803901e8     ldp        x20, x19, [sp, #0x70]
    // 00000001803901ec     ldp        x22, x21, [sp, #0x60]
    // 00000001803901f0     ldp        x24, x23, [sp, #0x50]
    // 00000001803901f4     add        sp, sp, #0x90
    // 00000001803901f8     ret
    volatile uint32_t* bne = patchfind_backwards(frame, 0x54000001, 0xff00001f, 0x10);
    if (bne) {
        *bne = 0xd2800000; // mov x0, #0
        return 0;
    }
    
    return 6;
}

void patch_bootloader(void* boot_image)
{
    strcpy((void*)((uintptr_t)boot_image + 0x200), "Stage2 KJC Loader");

    if (ipf_flag & 1) {
        if (sigcheck(boot_image)) {
            goto fail;
        }
        strcpy((void*)((uintptr_t)boot_image + 0x200), "Stage2 KJC loader");
    }

    // Trampoline patch
    bool tramp_done = false;
    for(volatile uint32_t *p = boot_image, *end = (volatile uint32_t*)((uintptr_t)boot_image + SAFE_TEXT_SIZE); p < end; ++p)
    {
        // Start by finding "movz x18, 0"
        if(*p == 0xd2800012)
        {
            // Make it load Pongo's base address instead
            *p = 0xb26107f2; // orr x18, xzr, 0x180000000
            // Now find the next ret
            for(; p < end; ++p)
            {
                if(*p == 0xd65f03c0)
                {
                    tramp_done = true;
                    break;
                }
            }
            if(!tramp_done)
            {
                goto fail;
            }
            // Patch it
            *p = 0xd61f0240; // br x18
            break;
        }
    }
    if(!tramp_done)
    {
        goto fail;
    }

    // Keep L3 SRAM around
    // /x 000040b900781e12000000b9000040b900001032000000b9001440b900000032001400b9:00fcffff00fcffff00fcffff00fcffff00fcffff00fcffff00fcffff00fcffff00fcffff
    for(volatile uint32_t *p = boot_image, *end = (volatile uint32_t*)((uintptr_t)boot_image + SAFE_TEXT_SIZE); p < end; ++p)
    {
        if
        (
            (p[0] & 0xfffffc00) == 0xb9400000 && // ldr wM, [xN]
            (p[1] & 0xfffffc00) == 0x121e7800 && // and wM, wM, 0xfffffffd
            (p[2] & 0xfffffc00) == 0xb9000000 && // str wM, [xN]
            (p[3] & 0xfffffc00) == 0xb9400000 && // ldr wM, [xN]
            (p[4] & 0xfffffc00) == 0x32100000 && // orr wM, wM, 0x10000
            (p[5] & 0xfffffc00) == 0xb9000000 && // str wM, [xN]
            (p[6] & 0xfffffc00) == 0xb9401400 && // ldr wM, [xN, 0x14]
            (p[7] & 0xfffffc00) == 0x32000000 && // orr wM, wM, 1
            (p[8] & 0xfffffc00) == 0xb9001400    // str wM, [xN, 0x14]
        )
        {
            need_to_release_L3_SRAM = 0x41;
            p[0] = 0xd65f03c0; // ret
            break;
        }
    }

    // Cursed fix for this god forsaken bootloader.
    // On A9 and A9X, if the code running between iBootStage1 and iBootStage2 takes more than
    // a given amount of time (1.5s?), then iBootStage2 will fail to initialise the APCIe link.
    // Hell knows why, but it can be fixed by resetting whatever underlying hardware there is,
    // and iBoot already contains the code to do that, but it only uses it in the iBEC profile.
    // So what we do here is find the function that sets the reset flag and patch it to always true.
    // This consists of:
    //  adr x8, 0x...
    //  nop
    //  {orr w9, wzr, 1 | mov w9, 1}
    //  strb w9, [x8]
    //  strb w0, [x8, 1]
    //  ret
    // We just turn the second store into "strb w9, [x8, 1]".
    // /x 080000101f2003d5e90300320901003900050039c0035fd6:1f00009fffffffffffffffffffffffffffffffffffffffff
    // /x 080000101f2003d5290080520901003900050039c0035fd6:1f00009fffffffffffffffffffffffffffffffffffffffff
    for(volatile uint32_t *p = boot_image, *end = (volatile uint32_t*)((uintptr_t)boot_image + SAFE_TEXT_SIZE); p < end; ++p)
    {
        if
        (
            (p[0] & 0x9f00001f) == 0x10000008 &&
             p[1] == 0xd503201f &&
            (p[2] == 0x52800029 || p[2] == 0x320003e9) &&
             p[3] == 0x39000109 &&
             p[4] == 0x39000500 &&
             p[5] == 0xd65f03c0
        )
        {
            p[4] = 0x39000509;
            break;
        }
    }

    // TrustZone patches.
    // We have two of them here, see patches.S for a device/version matrix.
    bool tz_done = false;
    for(volatile uint32_t *p = boot_image, *end = (volatile uint32_t*)((uintptr_t)boot_image + SAFE_TEXT_SIZE); p < end; ++p)
    {
        uint32_t op1 = p[0],
                 op2 = p[1],
                 op3 = p[2];

        // A7 (any version) and A8-A9 (iOS 10 and lower).
        // We look for the following sequence:
        //  str wN, [xM]
        //  ldr wT, [xM]
        //  tbz wT, 0, ...
        //  str wN, [xM, 4]
        //  ldr wS, [xM, 4]
        //  tbz wS, 0, ...
        // On iOS 7 specifically, there is an immediate generated in the middle,
        // and thus the second load and store have no offset:
        //  str wN, [xM]
        //  ldr wT, [xM]
        //  tbz wT, 0, ...
        //  movz xM, 0x200000000
        //  movk xM, 0x914
        //  str wN, [xM]
        //  ldr wS, [xM]
        //  tbz wS, 0, ...
        // We require that T and S are <16, and that the two tbz have positive offset.
        // /x 000000b9000040b900000036000400b9000440b900000036:00fcffff10fcffff0000fcff00fcffff10fcffff0000fcff
        // /x 000000b9000040b9000000364000c0d2802281f2000000b9000040b900000036:00fcffff10fcffff0000fcffe0ffffffe0ffffff00fcffff10fcffff0000fcff
        if((op1 & 0xfffffc00) == 0xb9000000 && (op2 & 0xfffffff0) == ((op1 & 0x000003e0) | 0xb9400000) && (op3 & 0xfffc001f) == ((op2 & 0x0000001f) | 0x36000000))
        {
            volatile uint32_t *one = p,
                              *two = p + 3;
            uint32_t op4 = two[0],
                     op5 = two[1];
            uint32_t imm = 1; // 1 << 2
            if(op4 == (((op1 & 0x000003e0) >> 5) | 0xd2c00040) && op5 == (((op1 & 0x000003e0) >> 5) | 0xf2812280))
            {
                two += 2;
                op4 = two[0];
                op5 = two[1];
                imm = 0;
            }
            if(op4 == ((op1 & 0x000003ff) | (imm << 10) | 0xb9000000) && (op5 & 0xfffffff0) == ((op1 & 0x000003e0) | (imm << 10) | 0xb9400000) && (two[2] & 0xfffc001f) == ((op5 & 0x0000001f) | 0x36000000))
            {
                // Nop them all out.
                one[0] = 0xd503201f;
                one[1] = 0xd503201f;
                one[2] = 0xd503201f;
                two[0] = 0xd503201f;
                two[1] = 0xd503201f;
                two[2] = 0xd503201f;
                tz_done = true;
                break;
            }
        }
        // A9X patch, any version.
        // The reason A9X is separate is because it has two sets of TZ registers
        // rather than just one, which makes for *very* different codegen!
        // The signature sequence we look for is:
        //  add xS, xD, 0x10
        //  orr xN, xM, xS
        //  str wT, [xN]
        // After that, there is a load from xN and a tbz based on bit 0 of the value.
        // Then we have another store, another load, but this time a tbnz because it's a loop.
        // In addition, there can be various other instructions scattered between these.
        // Only the block above seems to reliably get emitted contiguously.
        // /x c84200911a0308aa570300b9:00fcffff00fce0ff00fcffff
        else if((op1 & 0xfffffc00) == 0x91004000 && (op2 & 0xfffffc00) == (((op1 & 0x1f) << 16) | 0xaa000000) && (op3 & 0xffffffe0) == (((op2 & 0x1f) << 5) | 0xb9000000))
        {
            // Within a few instructions, there has to be a load from the same base reg as op3
            uint32_t ins = (op3 & 0x3e0) | 0xb9400000;
            uint32_t op = 0;
            volatile uint32_t *ldr = NULL;
            for(size_t i = 0; i < 4; ++i)
            {
                op = p[3 + i];
                if((op & 0xffffffe0) == ins)
                {
                    ldr = p + 3 + i;
                    break;
                }
            }
            if(!ldr)
            {
                goto fail;
            }
            // NOP the write and turn the load into an immediate move
            p[2] = 0xd503201f;
            *ldr = (op & 0x1f) | 0x52800020;

            // There is another store after this, with the same value register as op3, but possibly a different base register.
            ins = op3 & 0xfffffc1f;
            volatile uint32_t *str = NULL;
            for(size_t i = 1; i <= 8; ++i)
            {
                op = ldr[i];
                if((op & 0xfffffc1f) == ins)
                {
                    str = ldr + i;
                    break;
                }
            }
            if(!str)
            {
                goto fail;
            }
            // And another load like above
            ins = (op & 0x3e0) | 0xb9400000;
            ldr = NULL;
            for(size_t i = 1; i <= 4; ++i)
            {
                op = str[i];
                if((op & 0xffffffe0) == ins)
                {
                    ldr = str + i;
                    break;
                }
            }
            if(!ldr)
            {
                goto fail;
            }
            // Same patch
            *str = 0xd503201f;
            *ldr = (op & 0x1f) | 0x52800020;

            tz_done = true;
            break;
        }
        // A9X, early iOS 10
        // This SoC has the curious fact of having more than one AMCC
        // As such, Trustzone registers have to be locked twice, and we can
        // patchfind this through the loop in which it increases by 0x200000 (the difference between both AMCC base addr)
        // in other SoCs this is optimized out (please?) due to only 1 AMCC
        // early iOS 10 seems to only use X8 so this should be fine
        else if((op1 & 0xffffffff) == 0x91480108)
        {
            volatile uint32_t* curr = (uint32_t*)p;
            volatile uint32_t* tbz = (uint32_t*)(curr - 1);
            if ((*tbz & 0x7f000000) != 0x36000000) {
                break;
            }
            volatile uint32_t* ldr = (uint32_t*)(tbz - 1);
            volatile uint32_t* str = (uint32_t*)(tbz - 2);

            if ((*ldr & 0xbfc00000) != 0xb9400000 ||  (*str & 0xbfc00000) != 0xb9000000) {
                // not LDR | not STR
                break;
            }

            uint32_t tbz_reg = *tbz & 0x1f;
            uint32_t ldr_reg = *ldr & 0x1f;
            //uint32_t str_reg = (*str >> 5) & 0x1f; // base reg

            if(tbz_reg != ldr_reg) {
                // reg is not the same
                break;
            }

            // take 2, tbnz now

            volatile uint32_t *tbnz = NULL;
            for(size_t i = 1; i <= 10; ++i)
            {
                uint32_t op = curr[i];
                if((op & 0x7f000000) == 0x37000000)
                {
                    tbnz = &curr[i];
                    break;
                }
            }

            volatile uint32_t* ldr2 = (uint32_t*)(tbnz - 1);
            volatile uint32_t* str2 = (uint32_t*)(tbnz - 2);

            if ((*ldr2 & 0xbfc00000) != 0xb9400000 ||  (*str2 & 0xbfc00000) != 0xb9000000) {
                // not LDR || not STR
                break;
            }

            uint32_t tbnz_reg = *tbnz & 0x1f;
            uint32_t ldr2_reg = *ldr2 & 0x1f;
            //uint32_t str2_reg = (*str2 >> 5) & 0x1f; // base reg

            if(tbnz_reg != ldr2_reg) {
                // reg is not the same
                break;
            }

            // only now can we be sure we can patch this...
            // nop the str before the tbz
            *str = 0xd503201f;
            // turn the ldr into a mov reg, #1
            *ldr = (*ldr & 0x1f) | 0x52800020;
            // nop this too
            *str2 = 0xd503201f;
            // and make this a mov reg, #1 too
            *ldr2 = (*ldr2 & 0x1f) | 0x52800020;
            
            tz_done = true;
            break;
        }
    }

    iorvbar_yeet(boot_image);
    aes_keygen(boot_image);
    // Ultra dirty hack: 16K support = Reconfig Engine
    if(is_16k())
    {
        recfg_yoink(boot_image);
    }
    fuse_jump(boot_image);
    if(!tz_done)
    {
        antitrust(boot_image);
    }
    return;

fail:;
    __asm__ volatile("b ."); // TODO: better fail?
}

/* BSS is cleaned on _start, so we cannot rely on it. */
void* gboot_entry_point = (void*)0xddeeaaddbbeeeeff;
void* gboot_args = (void*)0xddeeaaddbbeeeeff;

_Noreturn void stage3_exit_to_el1_image(void *boot_args, void *boot_entry_point, void *trampoline) {
    if (*(uint8_t*)(gboot_args + 8 + 7)) {
        // kernel
        gboot_args = boot_args;
        gboot_entry_point = boot_entry_point;
    } else {
        // hypv
        *(void**)(gboot_args + 0x20) = boot_args;
        *(void**)(gboot_args + 0x28) = boot_entry_point;
        __asm__ volatile("smc 0"); // elevate to EL3
    }
    jump_to_image((uint64_t)gboot_entry_point, (uint64_t)gboot_args, (uint64_t)trampoline);
}

_Noreturn void trampoline_entry(void* boot_image, void* boot_args)
{
    if (!boot_args) {
        // bootloader
        patch_bootloader(boot_image);
        jump_to_image((uint64_t)boot_image, (uint64_t)boot_args, 0);
    } else {
        gboot_args = boot_args;
        gboot_entry_point = boot_image;
        setup_el1((uint64_t)boot_image, (uint64_t)boot_args, main);
    }
}
