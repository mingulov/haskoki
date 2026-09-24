{- | Measured C scalar/layout facts from the pinned headers.
__hsc2hs__-generated layout types: every size, alignment and offset below
is measured from @spec/vendor@ at build time, never assumed.
The authoritative layout/prototype checks live in the independent C
probes (@tests/c/layout_*.c@); this module gives the Haskell side the
same measured shapes (scalar widths, version/info records, function-list
extents) for the model and marshalling layers.

At the ABI boundary 'CkUlong' is a measured C @unsigned long@ (LP64:
8 bytes), not unconditionally 'Word64' (see @03-abi-and-runtime.md@
section 3). Internally, the model normalizes to explicit-width values with
checked conversion both ways.
-}
{-# LANGUAGE ForeignFunctionInterface #-}

module Haskoki.FFI.Types
  ( -- * Scalar newtypes (all CK_ULONG-wide at the boundary)
    CkUlong (..)
  , CkRv (..)
  , CkFlags (..)
  , CkSlotId (..)
  , CkSessionHandle (..)
  , CkObjectHandle (..)
  , CkMechanismType (..)
    -- * Measured scalar facts
  , ckUlongSize
  , ckUlongAlignment
    -- * Sentinels (measured values)
  , ckUnavailableInformation
  , ckEffectivelyInfinite
  , ckInvalidHandle
    -- * Records
  , CkVersion (..)
  , CkInfo (..)
  , ckInfoSize
  , ckInfoFlagsOffset
    -- * Function-list extents
  , ckFunctionListSize
  , ckFunctionList30Size
  , ckFunctionList32Size
  , ckFunctionListInitOffset
  ) where

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include "pkcs11.h"

import Data.Word (Word8)
import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Array (peekArray, pokeArray)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Foreign.Storable (Storable (..))

-- | Measured C @unsigned long@ wrapper. All CK_ULONG-typedef'd quantities
-- cross the boundary through this (or a meaning-distinct sibling below).
newtype CkUlong = CkUlong { unCkUlong :: CULong }
  deriving (Eq, Ord, Show)

-- | Function return value (meaning-distinct from a bare length).
newtype CkRv = CkRv { unCkRv :: CULong }
  deriving (Eq, Ord, Show)

-- | Bit-flag word.
newtype CkFlags = CkFlags { unCkFlags :: CULong }
  deriving (Eq, Ord, Show)

-- | Slot identifier.
newtype CkSlotId = CkSlotId { unCkSlotId :: CULong }
  deriving (Eq, Ord, Show)

-- | Session handle (opaque to callers).
newtype CkSessionHandle = CkSessionHandle { unCkSessionHandle :: CULong }
  deriving (Eq, Ord, Show)

-- | Object handle (opaque to callers).
newtype CkObjectHandle = CkObjectHandle { unCkObjectHandle :: CULong }
  deriving (Eq, Ord, Show)

-- | Mechanism identifier.
newtype CkMechanismType = CkMechanismType { unCkMechanismType :: CULong }
  deriving (Eq, Ord, Show)

-- | Measured @sizeof(CK_ULONG)@.
ckUlongSize :: Int
ckUlongSize = #{size CK_ULONG}

-- | Measured @alignof(CK_ULONG)@.
ckUlongAlignment :: Int
ckUlongAlignment = #{alignment CK_ULONG}

instance Storable CkUlong where
  sizeOf _ = #{size CK_ULONG}
  alignment _ = #{alignment CK_ULONG}
  peek p = CkUlong <$> peek (castPtr p)
  poke p (CkUlong v) = poke (castPtr p) v

instance Storable CkRv where
  sizeOf _ = #{size CK_RV}
  alignment _ = #{alignment CK_RV}
  peek p = CkRv <$> peek (castPtr p)
  poke p (CkRv v) = poke (castPtr p) v

instance Storable CkFlags where
  sizeOf _ = #{size CK_FLAGS}
  alignment _ = #{alignment CK_FLAGS}
  peek p = CkFlags <$> peek (castPtr p)
  poke p (CkFlags v) = poke (castPtr p) v

instance Storable CkSlotId where
  sizeOf _ = #{size CK_SLOT_ID}
  alignment _ = #{alignment CK_SLOT_ID}
  peek p = CkSlotId <$> peek (castPtr p)
  poke p (CkSlotId v) = poke (castPtr p) v

instance Storable CkSessionHandle where
  sizeOf _ = #{size CK_SESSION_HANDLE}
  alignment _ = #{alignment CK_SESSION_HANDLE}
  peek p = CkSessionHandle <$> peek (castPtr p)
  poke p (CkSessionHandle v) = poke (castPtr p) v

instance Storable CkObjectHandle where
  sizeOf _ = #{size CK_OBJECT_HANDLE}
  alignment _ = #{alignment CK_OBJECT_HANDLE}
  peek p = CkObjectHandle <$> peek (castPtr p)
  poke p (CkObjectHandle v) = poke (castPtr p) v

instance Storable CkMechanismType where
  sizeOf _ = #{size CK_MECHANISM_TYPE}
  alignment _ = #{alignment CK_MECHANISM_TYPE}
  peek p = CkMechanismType <$> peek (castPtr p)
  poke p (CkMechanismType v) = poke (castPtr p) v

-- | Measured @CK_UNAVAILABLE_INFORMATION@.
ckUnavailableInformation :: CkUlong
ckUnavailableInformation = CkUlong #{const CK_UNAVAILABLE_INFORMATION}

-- | Measured @CK_EFFECTIVELY_INFINITE@.
ckEffectivelyInfinite :: CkUlong
ckEffectivelyInfinite = CkUlong #{const CK_EFFECTIVELY_INFINITE}

-- | Measured @CK_INVALID_HANDLE@.
ckInvalidHandle :: CkUlong
ckInvalidHandle = CkUlong #{const CK_INVALID_HANDLE}

-- | Library/interface version pair.
data CkVersion = CkVersion
  { ckMajor :: !Word8
  , ckMinor :: !Word8
  } deriving (Eq, Ord, Show)

instance Storable CkVersion where
  sizeOf _ = #{size CK_VERSION}
  alignment _ = #{alignment CK_VERSION}
  peek p = CkVersion <$> #{peek CK_VERSION, major} p
                       <*> #{peek CK_VERSION, minor} p
  poke p v = do
    #{poke CK_VERSION, major} p (ckMajor v)
    #{poke CK_VERSION, minor} p (ckMinor v)

-- | Provider metadata record. Fixed-size space-padded fields are plain
-- checked-length byte lists at this layer (the model decodes them).
data CkInfo = CkInfo
  { ckCryptokiVersion :: !CkVersion
  , ckManufacturerId :: ![Word8] -- ^ exactly 32 bytes
  , ckInfoFlags :: !CkFlags
  , ckLibraryDescription :: ![Word8] -- ^ exactly 32 bytes
  , ckLibraryVersion :: !CkVersion
  } deriving (Eq, Show)

-- | Measured @sizeof(CK_INFO)@.
ckInfoSize :: Int
ckInfoSize = #{size CK_INFO}

-- | Measured @offsetof(CK_INFO, flags)@.
ckInfoFlagsOffset :: Int
ckInfoFlagsOffset = #{offset CK_INFO, flags}

instance Storable CkInfo where
  sizeOf _ = #{size CK_INFO}
  alignment _ = #{alignment CK_INFO}
  peek p = CkInfo
    <$> peek (p `plusPtr` #{offset CK_INFO, cryptokiVersion})
    <*> peekArray 32 (p `plusPtr` #{offset CK_INFO, manufacturerID})
    <*> peek (p `plusPtr` #{offset CK_INFO, flags} :: Ptr CkFlags)
    <*> peekArray 32 (p `plusPtr` #{offset CK_INFO, libraryDescription})
    <*> peek (p `plusPtr` #{offset CK_INFO, libraryVersion})
  poke p v = do
    poke (p `plusPtr` #{offset CK_INFO, cryptokiVersion}) (ckCryptokiVersion v)
    pokeArray (p `plusPtr` #{offset CK_INFO, manufacturerID})
      (take 32 (ckManufacturerId v ++ repeat 0x20))
    poke (p `plusPtr` #{offset CK_INFO, flags} :: Ptr CkFlags) (ckInfoFlags v)
    pokeArray (p `plusPtr` #{offset CK_INFO, libraryDescription})
      (take 32 (ckLibraryDescription v ++ repeat 0x20))
    poke (p `plusPtr` #{offset CK_INFO, libraryVersion}) (ckLibraryVersion v)

-- | Measured @sizeof(CK_FUNCTION_LIST)@ (68-entry legacy layout).
ckFunctionListSize :: Int
ckFunctionListSize = #{size CK_FUNCTION_LIST}

-- | Measured @sizeof(CK_FUNCTION_LIST_3_0)@ (92 entries; also 3.1's layout).
ckFunctionList30Size :: Int
ckFunctionList30Size = #{size CK_FUNCTION_LIST_3_0}

-- | Measured @sizeof(CK_FUNCTION_LIST_3_2)@ (104 entries).
ckFunctionList32Size :: Int
ckFunctionList32Size = #{size CK_FUNCTION_LIST_3_2}

-- | Measured @offsetof(CK_FUNCTION_LIST, C_Initialize)@.
ckFunctionListInitOffset :: Int
ckFunctionListInitOffset = #{offset CK_FUNCTION_LIST, C_Initialize}
