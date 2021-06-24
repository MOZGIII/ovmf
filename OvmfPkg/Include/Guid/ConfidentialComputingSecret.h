 /** @file
   UEFI Configuration Table for exposing the SEV Launch Secret location to UEFI
   applications (boot loaders).

   Copyright (C) 2020 James Bottomley, IBM Corporation.
   SPDX-License-Identifier: BSD-2-Clause-Patent
 **/

#ifndef CONFIDENTIAL_COMPUTING_SECRET_H_
#define CONFIDENTIAL_COMPUTING_SECRET_H_

#include <Uefi/UefiBaseType.h>

#define CONFIDENTIAL_COMPUTING_SECRET_GUID              \
  { 0xadf956ad,                                         \
    0xe98c,                                             \
    0x484c,                                             \
    { 0xae, 0x11, 0xb5, 0x1c, 0x7d, 0x33, 0x64, 0x47 }, \
  }

#define CONFIDENTIAL_COMPUTING_BLOB_GUID                \
  { 0x067b1f5f,                                         \
    0xcf26,                                             \
    0x44c5,                                             \
    { 0x85, 0x54, 0x93, 0xd7, 0x77, 0x91, 0x2d, 0x42 }, \
  }

typedef struct {
  UINT64 Base;
  UINT64 Size;
} CONFIDENTIAL_COMPUTING_SECRET_LOCATION;

typedef struct {
  UINT32  Header;
  UINT16  Version;
  UINT16  Reserved1;
  UINT64  SecretsPhysicalAddress;
  UINT32  SecretsSize;
  UINT64  CpuidPhysicalAddress;
  UINT32  CpuidLSize;
} CONFIDENTIAL_COMPUTING_BLOB_LOCATION;

extern EFI_GUID gConfidentialComputingSecretGuid;
extern EFI_GUID gConfidentialComputingBlobGuid;

#endif // SEV_LAUNCH_SECRET_H_
