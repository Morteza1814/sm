/* Keystone-to-LOC lifetime transport for gem5 RV64 full-system simulation.
 * The M5OP is accepted only inside the protected M-mode monitor window.
 * This does not add host-buffer transfers or a hardware device interface.
 */
#include "../../enclave.h"
#include "../../assert.h"

static uintptr_t loc_call(uintptr_t action, uintptr_t eid,
                          uintptr_t arg1, uintptr_t arg2)
{
  register uintptr_t a0 __asm__("a0") = action;
  register uintptr_t a1 __asm__("a1") = eid;
  register uintptr_t a2 __asm__("a2") = arg1;
  register uintptr_t a3 __asm__("a3") = arg2;
  /* M5OP_PIM_ENCLAVE (0x6a), using gem5's RISC-V M5OP encoding. */
  __asm__ volatile(".word 0xd400007b" : "+r"(a0)
                   : "r"(a1), "r"(a2), "r"(a3) : "memory");
  return a0;
}

unsigned long platform_init_global_once() { return 0; }
unsigned long platform_init_global() { return 0; }

void platform_init_enclave(struct enclave *enclave)
{
  enclave->ped.loc_principal = 0;
}

unsigned long platform_create_enclave(struct enclave *enclave)
{
  sm_assert(enclave->ped.loc_principal == 0);
  enclave->ped.loc_principal = loc_call(1, enclave->eid,
      enclave->pa_params.dram_base, enclave->pa_params.dram_size);
  return enclave->ped.loc_principal ? SBI_ERR_SM_ENCLAVE_SUCCESS :
                                     SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
}

void platform_destroy_enclave(struct enclave *enclave)
{
  const uintptr_t principal = enclave->ped.loc_principal;
  if (principal) {
    // This hook precedes the monitor's EPM scrub and PMP/EID release. Failed
    // creation validation also calls it, so pending registrations are retired.
    sm_assert(loc_call(4, enclave->eid, principal, 0) == principal);
    enclave->ped.loc_principal = 0;
  }
}

void platform_switch_to_enclave(struct enclave *enclave)
{
  const uintptr_t principal = enclave->ped.loc_principal;
  sm_assert(principal && loc_call(2, enclave->eid, principal, 0) == principal);
}

void platform_switch_from_enclave(struct enclave *enclave)
{
  const uintptr_t principal = enclave->ped.loc_principal;
  sm_assert(principal && loc_call(3, enclave->eid, principal, 0) == principal);
}

uint64_t platform_random()
{
  // Same test-only entropy as the generic platform; no cryptographic claim.
  static uint64_t w = 0;
  unsigned long cycles;
  __asm__ volatile("rdcycle %0" : "=r"(cycles));
  uint64_t x = cycles;
  x *= x;
  x += (w += 0xb5ad4eceda1ce2a9ULL);
  return (x >> 32) | (x << 32);
}
