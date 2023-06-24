/** @file

  Blob verifier library that uses SEV hashes table.  The hashes table holds the
  allowed hashes of the kernel, initrd, and cmdline blobs.

  Copyright (C) 2021, IBM Corporation

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/BaseCryptLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/BlobVerifierLib.h>

/**
  The SEV Hashes table must be in encrypted memory and has the table
  and its entries described by

  <GUID>|UINT16 <len>|<data>

  With the whole table GUID being 9438d606-4f22-4cc9-b479-a793d411fd21

  The current possible table entries are for the kernel, the initrd
  and the cmdline:

  4de79437-abd2-427f-b835-d5b172d2045b  kernel
  44baf731-3a2f-4bd7-9af1-41e29169781d  initrd
  97d02dd8-bd20-4c94-aa78-e7714d36ab2a  cmdline

  The size of the entry is used to identify the hash, but the
  expectation is that it will be 32 bytes of SHA-256.
**/

#define SEV_HASH_TABLE_GUID \
  (GUID) { 0x9438d606, 0x4f22, 0x4cc9, { 0xb4, 0x79, 0xa7, 0x93, 0xd4, 0x11, 0xfd, 0x21 } }
#define SEV_KERNEL_HASH_GUID \
  (GUID) { 0x4de79437, 0xabd2, 0x427f, { 0xb8, 0x35, 0xd5, 0xb1, 0x72, 0xd2, 0x04, 0x5b } }
#define SEV_INITRD_HASH_GUID \
  (GUID) { 0x44baf731, 0x3a2f, 0x4bd7, { 0x9a, 0xf1, 0x41, 0xe2, 0x91, 0x69, 0x78, 0x1d } }
#define SEV_CMDLINE_HASH_GUID \
  (GUID) { 0x97d02dd8, 0xbd20, 0x4c94, { 0xaa, 0x78, 0xe7, 0x71, 0x4d, 0x36, 0xab, 0x2a } }

STATIC CONST EFI_GUID  mSevKernelHashGuid  = SEV_KERNEL_HASH_GUID;
STATIC CONST EFI_GUID  mSevInitrdHashGuid  = SEV_INITRD_HASH_GUID;
STATIC CONST EFI_GUID  mSevCmdlineHashGuid = SEV_CMDLINE_HASH_GUID;

#pragma pack (1)
typedef struct {
  GUID      Guid;
  UINT16    Len;
  UINT8     Data[];
} HASH_TABLE;
#pragma pack ()

STATIC HASH_TABLE  *mHashesTable;
STATIC UINT16      mHashesTableSize;

STATIC
CONST GUID *
FindBlobEntryGuid (
  IN  CONST CHAR16  *BlobName
  )
{
  if (StrCmp (BlobName, L"kernel") == 0) {
    return &mSevKernelHashGuid;
  } else if (StrCmp (BlobName, L"initrd") == 0) {
    return &mSevInitrdHashGuid;
  } else if (StrCmp (BlobName, L"cmdline") == 0) {
    return &mSevCmdlineHashGuid;
  } else {
    return NULL;
  }
}

/**
  Verify blob from an external source.

  @param[in] BlobName           The name of the blob
  @param[in] Buf                The data of the blob
  @param[in] BufSize            The size of the blob in bytes

  @retval EFI_SUCCESS           The blob was verified successfully.
  @retval EFI_ACCESS_DENIED     The blob could not be verified, and therefore
                                should be considered non-secure.
**/
EFI_STATUS
EFIAPI
VerifyBlob (
  IN  CONST CHAR16  *BlobName,
  IN  CONST VOID    *Buf,
  IN  UINT32        BufSize
  )
{
  CONST GUID  *Guid;
  INT32       Remaining;
  HASH_TABLE  *Entry;

  if ((mHashesTable == NULL) || (mHashesTableSize == 0)) {
    DEBUG ((
      DEBUG_ERROR,
      "%a: Verifier called but no hashes table discoverd in MEMFD\n",
      __FUNCTION__
      ));
    return EFI_ACCESS_DENIED;
  }

  Guid = FindBlobEntryGuid (BlobName);
  if (Guid == NULL) {
    DEBUG ((
      DEBUG_ERROR,
      "%a: Unknown blob name \"%s\"\n",
      __FUNCTION__,
      BlobName
      ));
    return EFI_ACCESS_DENIED;
  }

  //
  // Remaining is INT32 to catch underflow in case Entry->Len has a
  // very high UINT16 value
  //
  for (Entry = mHashesTable, Remaining = mHashesTableSize;
       Remaining >= sizeof *Entry && Remaining >= Entry->Len;
       Remaining -= Entry->Len,
       Entry = (HASH_TABLE *)((UINT8 *)Entry + Entry->Len))
  {
    UINTN       EntrySize;
    EFI_STATUS  Status;
    UINT8       Hash[SHA256_DIGEST_SIZE];

    if (!CompareGuid (&Entry->Guid, Guid)) {
      continue;
    }

    DEBUG ((DEBUG_INFO, "%a: Found GUID %g in table\n", __FUNCTION__, Guid));

    EntrySize = Entry->Len - sizeof Entry->Guid - sizeof Entry->Len;
    if (EntrySize != SHA256_DIGEST_SIZE) {
      DEBUG ((
        DEBUG_ERROR,
        "%a: Hash has the wrong size %d != %d\n",
        __FUNCTION__,
        EntrySize,
        SHA256_DIGEST_SIZE
        ));
      return EFI_ACCESS_DENIED;
    }

    //
    // Calculate the buffer's hash and verify that it is identical to the
    // expected hash table entry
    //
    Sha256HashAll (Buf, BufSize, Hash);

    if (CompareMem (Entry->Data, Hash, EntrySize) == 0) {
      Status = EFI_SUCCESS;
      DEBUG ((
        DEBUG_INFO,
        "%a: Hash comparison succeeded for \"%s\"\n",
        __FUNCTION__,
        BlobName
        ));
    } else {
      Status = EFI_ACCESS_DENIED;

      DEBUG ((
        DEBUG_INFO,
        "%a: Passed hash: 0x"\
        "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X" \
        "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X" \
        "\n",
        __FUNCTION__,
        Entry->Data[0],
        Entry->Data[1],
        Entry->Data[2],
        Entry->Data[3],
        Entry->Data[4],
        Entry->Data[5],
        Entry->Data[6],
        Entry->Data[7],
        Entry->Data[8],
        Entry->Data[9],
        Entry->Data[10],
        Entry->Data[11],
        Entry->Data[12],
        Entry->Data[13],
        Entry->Data[14],
        Entry->Data[15],
        Entry->Data[16],
        Entry->Data[17],
        Entry->Data[18],
        Entry->Data[19],
        Entry->Data[20],
        Entry->Data[21],
        Entry->Data[22],
        Entry->Data[23],
        Entry->Data[24],
        Entry->Data[25],
        Entry->Data[26],
        Entry->Data[27],
        Entry->Data[28],
        Entry->Data[29],
        Entry->Data[30],
        Entry->Data[31]
        ));

      DEBUG ((
        DEBUG_INFO,
        "%a: Computed hash: 0x" \
        "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X" \
        "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X" \
        "\n",
        __FUNCTION__,
        Hash[0],
        Hash[1],
        Hash[2],
        Hash[3],
        Hash[4],
        Hash[5],
        Hash[6],
        Hash[7],
        Hash[8],
        Hash[9],
        Hash[10],
        Hash[11],
        Hash[12],
        Hash[13],
        Hash[14],
        Hash[15],
        Hash[16],
        Hash[17],
        Hash[18],
        Hash[19],
        Hash[20],
        Hash[21],
        Hash[22],
        Hash[23],
        Hash[24],
        Hash[25],
        Hash[26],
        Hash[27],
        Hash[28],
        Hash[29],
        Hash[30],
        Hash[31]
        ));

      DEBUG ((
        DEBUG_ERROR,
        "%a: Hash comparison failed for \"%s\"\n",
        __FUNCTION__,
        BlobName
        ));
    }

    return Status;
  }

  DEBUG ((
    DEBUG_ERROR,
    "%a: Hash GUID %g not found in table\n",
    __FUNCTION__,
    Guid
    ));
  return EFI_ACCESS_DENIED;
}

/**
  Locate the SEV hashes table.

  This function always returns success, even if the table can't be found.  The
  subsequent VerifyBlob calls will fail if no table was found.

  @retval RETURN_SUCCESS   The hashes table is set up correctly, or there is no
                           hashes table
**/
RETURN_STATUS
EFIAPI
BlobVerifierLibSevHashesConstructor (
  VOID
  )
{
  HASH_TABLE  *Ptr;
  UINT32      Size;

  mHashesTable     = NULL;
  mHashesTableSize = 0;

  Ptr  = (void *)(UINTN)FixedPcdGet64 (PcdQemuHashTableBase);
  Size = FixedPcdGet32 (PcdQemuHashTableSize);

  if ((Ptr == NULL) || (Size < sizeof *Ptr) ||
      !CompareGuid (&Ptr->Guid, &SEV_HASH_TABLE_GUID) ||
      (Ptr->Len < sizeof *Ptr) || (Ptr->Len > Size))
  {
    return RETURN_SUCCESS;
  }

  DEBUG ((
    DEBUG_INFO,
    "%a: Found injected hashes table in secure location\n",
    __FUNCTION__
    ));

  mHashesTable     = (HASH_TABLE *)Ptr->Data;
  mHashesTableSize = Ptr->Len - sizeof Ptr->Guid - sizeof Ptr->Len;

  DEBUG ((
    DEBUG_VERBOSE,
    "%a: mHashesTable=0x%p, Size=%u\n",
    __FUNCTION__,
    mHashesTable,
    mHashesTableSize
    ));

  return RETURN_SUCCESS;
}
