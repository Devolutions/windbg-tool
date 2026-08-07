#![allow(non_snake_case)]

use std::{
    ffi::c_void,
    mem::size_of,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use anyhow::{bail, ensure, Context};
use serde::Serialize;
use windows::{
    core::{IUnknown, Interface, GUID, HRESULT, PCWSTR},
    Win32::{
        Foundation::{
            FreeLibrary, E_ACCESSDENIED, E_INVALIDARG, E_NOTIMPL, E_POINTER, E_UNEXPECTED, HMODULE,
            S_FALSE,
        },
        Storage::FileSystem::{
            GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FFI_SIGNATURE,
            VS_FIXEDFILEINFO,
        },
        System::{
            Diagnostics::Debug::{Extensions::*, CONTEXT},
            LibraryLoader::{
                GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            },
            Memory::{VirtualAllocEx, VirtualFreeEx},
            SystemInformation::IMAGE_FILE_MACHINE_AMD64,
        },
    },
};
use windows_core::IUnknown_Vtbl;

use crate::DebuggerSession;

const CLRDATA_METHNOTIFY_GENERATED: u32 = 0x0000_0001;
const CLRDATA_METHNOTIFY_DISCARDED: u32 = 0x0000_0002;
const CLRDATA_NOTIFY_ON_MODULE_LOAD: u32 = 0x0000_0001;
const MAX_WIDE_CHARS: usize = 1024;
const MAX_SIGNATURE_HEX_CHARS: usize = 1024;
const MAX_METHOD_CANDIDATES: usize = 8;

// These declarations are the exact prefixes used from the MIT-licensed CoreCLR
// clrdata.idl/xclrdata.idl contracts. DAC interfaces are COM ABI contracts, so every
// preceding method must remain in its original order even when this module does not call it.
#[windows::core::interface("3E11CCEE-D08B-43E5-AF01-32717A64DA03")]
unsafe trait ICLRDataTarget: IUnknown {
    unsafe fn GetMachineType(&self, machine_type: *mut u32) -> HRESULT;
    unsafe fn GetPointerSize(&self, pointer_size: *mut u32) -> HRESULT;
    unsafe fn GetImageBase(&self, image_path: PCWSTR, base_address: *mut u64) -> HRESULT;
    unsafe fn ReadVirtual(
        &self,
        address: u64,
        buffer: *mut u8,
        bytes_requested: u32,
        bytes_read: *mut u32,
    ) -> HRESULT;
    unsafe fn WriteVirtual(
        &self,
        address: u64,
        buffer: *mut u8,
        bytes_requested: u32,
        bytes_written: *mut u32,
    ) -> HRESULT;
    unsafe fn GetTLSValue(&self, thread_id: u32, index: u32, value: *mut u64) -> HRESULT;
    unsafe fn SetTLSValue(&self, thread_id: u32, index: u32, value: u64) -> HRESULT;
    unsafe fn GetCurrentThreadID(&self, thread_id: *mut u32) -> HRESULT;
    unsafe fn GetThreadContext(
        &self,
        thread_id: u32,
        context_flags: u32,
        context_size: u32,
        context: *mut u8,
    ) -> HRESULT;
    unsafe fn SetThreadContext(
        &self,
        thread_id: u32,
        context_size: u32,
        context: *mut u8,
    ) -> HRESULT;
    unsafe fn Request(
        &self,
        request_code: u32,
        input_size: u32,
        input: *mut u8,
        output_size: u32,
        output: *mut u8,
    ) -> HRESULT;
}

#[windows::core::interface("6D05FAE3-189C-4630-A6DC-1C251E1C01AB")]
unsafe trait ICLRDataTarget2: ICLRDataTarget {
    unsafe fn AllocVirtual(
        &self,
        address: u64,
        size: u32,
        type_flags: u32,
        protect_flags: u32,
        allocation: *mut u64,
    ) -> HRESULT;
    unsafe fn FreeVirtual(&self, address: u64, size: u32, type_flags: u32) -> HRESULT;
}

#[windows::core::interface("5C552AB6-FC09-4CB3-8E36-22FA03C798B7")]
unsafe trait IXCLRDataProcess: IUnknown {
    unsafe fn Flush(&self) -> HRESULT;
    unsafe fn StartEnumTasks(&self, handle: *mut u64) -> HRESULT;
    unsafe fn EnumTask(&self, handle: *mut u64, task: *mut *mut c_void) -> HRESULT;
    unsafe fn EndEnumTasks(&self, handle: u64) -> HRESULT;
    unsafe fn GetTaskByOSThreadID(&self, thread_id: u32, task: *mut *mut c_void) -> HRESULT;
    unsafe fn GetTaskByUniqueID(&self, task_id: u64, task: *mut *mut c_void) -> HRESULT;
    unsafe fn GetFlags(&self, flags: *mut u32) -> HRESULT;
    unsafe fn IsSameObject(&self, process: *mut c_void) -> HRESULT;
    unsafe fn GetManagedObject(&self, value: *mut *mut c_void) -> HRESULT;
    unsafe fn GetDesiredExecutionState(&self, state: *mut u32) -> HRESULT;
    unsafe fn SetDesiredExecutionState(&self, state: u32) -> HRESULT;
    unsafe fn GetAddressType(&self, address: u64, address_type: *mut u32) -> HRESULT;
    unsafe fn GetRuntimeNameByAddress(
        &self,
        address: u64,
        flags: u32,
        buffer_length: u32,
        name_length: *mut u32,
        name: *mut u16,
        displacement: *mut u64,
    ) -> HRESULT;
    unsafe fn StartEnumAppDomains(&self, handle: *mut u64) -> HRESULT;
    unsafe fn EnumAppDomain(&self, handle: *mut u64, app_domain: *mut *mut c_void) -> HRESULT;
    unsafe fn EndEnumAppDomains(&self, handle: u64) -> HRESULT;
    unsafe fn GetAppDomainByUniqueID(&self, id: u64, app_domain: *mut *mut c_void) -> HRESULT;
    unsafe fn StartEnumAssemblies(&self, handle: *mut u64) -> HRESULT;
    unsafe fn EnumAssembly(&self, handle: *mut u64, assembly: *mut *mut c_void) -> HRESULT;
    unsafe fn EndEnumAssemblies(&self, handle: u64) -> HRESULT;
    unsafe fn StartEnumModules(&self, handle: *mut u64) -> HRESULT;
    unsafe fn EnumModule(&self, handle: *mut u64, module: *mut *mut c_void) -> HRESULT;
    unsafe fn EndEnumModules(&self, handle: u64) -> HRESULT;
    unsafe fn GetModuleByAddress(&self, address: u64, module: *mut *mut c_void) -> HRESULT;
    unsafe fn Reserved24(&self) -> HRESULT;
    unsafe fn Reserved25(&self) -> HRESULT;
    unsafe fn Reserved26(&self) -> HRESULT;
    unsafe fn Reserved27(&self) -> HRESULT;
    unsafe fn Reserved28(&self) -> HRESULT;
    unsafe fn Reserved29(&self) -> HRESULT;
    unsafe fn Reserved30(&self) -> HRESULT;
    unsafe fn Reserved31(&self) -> HRESULT;
    unsafe fn Reserved32(&self) -> HRESULT;
    unsafe fn Reserved33(&self) -> HRESULT;
    unsafe fn Reserved34(&self) -> HRESULT;
    unsafe fn Reserved35(&self) -> HRESULT;
    unsafe fn Reserved36(&self) -> HRESULT;
    unsafe fn GetOtherNotificationFlags(&self, flags: *mut u32) -> HRESULT;
    unsafe fn SetOtherNotificationFlags(&self, flags: u32) -> HRESULT;
}

#[windows::core::interface("88E32849-0A0A-4CB0-9022-7CD2E9E139E2")]
unsafe trait IXCLRDataModule: IUnknown {
    unsafe fn StartEnumAssemblies(&self, handle: *mut u64) -> HRESULT;
    unsafe fn EnumAssembly(&self, handle: *mut u64, assembly: *mut *mut c_void) -> HRESULT;
    unsafe fn EndEnumAssemblies(&self, handle: u64) -> HRESULT;
    unsafe fn StartEnumTypeDefinitions(&self, handle: *mut u64) -> HRESULT;
    unsafe fn EnumTypeDefinition(
        &self,
        handle: *mut u64,
        type_definition: *mut *mut c_void,
    ) -> HRESULT;
    unsafe fn EndEnumTypeDefinitions(&self, handle: u64) -> HRESULT;
    unsafe fn StartEnumTypeInstances(&self, app_domain: *mut c_void, handle: *mut u64) -> HRESULT;
    unsafe fn EnumTypeInstance(&self, handle: *mut u64, type_instance: *mut *mut c_void)
        -> HRESULT;
    unsafe fn EndEnumTypeInstances(&self, handle: u64) -> HRESULT;
    unsafe fn StartEnumTypeDefinitionsByName(
        &self,
        name: PCWSTR,
        flags: u32,
        handle: *mut u64,
    ) -> HRESULT;
    unsafe fn EnumTypeDefinitionByName(
        &self,
        handle: *mut u64,
        type_definition: *mut *mut c_void,
    ) -> HRESULT;
    unsafe fn EndEnumTypeDefinitionsByName(&self, handle: u64) -> HRESULT;
    unsafe fn StartEnumTypeInstancesByName(
        &self,
        name: PCWSTR,
        flags: u32,
        app_domain: *mut c_void,
        handle: *mut u64,
    ) -> HRESULT;
    unsafe fn EnumTypeInstanceByName(
        &self,
        handle: *mut u64,
        type_instance: *mut *mut c_void,
    ) -> HRESULT;
    unsafe fn EndEnumTypeInstancesByName(&self, handle: u64) -> HRESULT;
    unsafe fn GetTypeDefinitionByToken(
        &self,
        token: u32,
        type_definition: *mut *mut c_void,
    ) -> HRESULT;
    unsafe fn StartEnumMethodDefinitionsByName(
        &self,
        name: PCWSTR,
        flags: u32,
        handle: *mut u64,
    ) -> HRESULT;
    unsafe fn EnumMethodDefinitionByName(
        &self,
        handle: *mut u64,
        method: *mut *mut c_void,
    ) -> HRESULT;
    unsafe fn EndEnumMethodDefinitionsByName(&self, handle: u64) -> HRESULT;
    unsafe fn StartEnumMethodInstancesByName(
        &self,
        name: PCWSTR,
        flags: u32,
        app_domain: *mut c_void,
        handle: *mut u64,
    ) -> HRESULT;
    unsafe fn EnumMethodInstanceByName(
        &self,
        handle: *mut u64,
        method: *mut *mut c_void,
    ) -> HRESULT;
    unsafe fn EndEnumMethodInstancesByName(&self, handle: u64) -> HRESULT;
    unsafe fn GetMethodDefinitionByToken(&self, token: u32, method: *mut *mut c_void) -> HRESULT;
    unsafe fn StartEnumDataByName(
        &self,
        name: PCWSTR,
        flags: u32,
        app_domain: *mut c_void,
        task: *mut c_void,
        handle: *mut u64,
    ) -> HRESULT;
    unsafe fn EnumDataByName(&self, handle: *mut u64, value: *mut *mut c_void) -> HRESULT;
    unsafe fn EndEnumDataByName(&self, handle: u64) -> HRESULT;
    unsafe fn GetName(&self, buffer_length: u32, name_length: *mut u32, name: *mut u16) -> HRESULT;
    unsafe fn GetFileName(
        &self,
        buffer_length: u32,
        name_length: *mut u32,
        name: *mut u16,
    ) -> HRESULT;
}

#[windows::core::interface("AAF60008-FB2C-420B-8FB1-42D244A54A97")]
unsafe trait IXCLRDataMethodDefinition: IUnknown {
    unsafe fn GetTypeDefinition(&self, type_definition: *mut *mut c_void) -> HRESULT;
    unsafe fn StartEnumInstances(&self, app_domain: *mut c_void, handle: *mut u64) -> HRESULT;
    unsafe fn EnumInstance(&self, handle: *mut u64, instance: *mut *mut c_void) -> HRESULT;
    unsafe fn EndEnumInstances(&self, handle: u64) -> HRESULT;
    unsafe fn GetName(
        &self,
        flags: u32,
        buffer_length: u32,
        name_length: *mut u32,
        name: *mut u16,
    ) -> HRESULT;
    unsafe fn GetTokenAndScope(&self, token: *mut u32, module: *mut *mut c_void) -> HRESULT;
    unsafe fn GetFlags(&self, flags: *mut u32) -> HRESULT;
    unsafe fn IsSameObject(&self, method: *mut c_void) -> HRESULT;
    unsafe fn GetLatestEnCVersion(&self, version: *mut u32) -> HRESULT;
    unsafe fn StartEnumExtents(&self, handle: *mut u64) -> HRESULT;
    unsafe fn EnumExtent(&self, handle: *mut u64, extent: *mut c_void) -> HRESULT;
    unsafe fn EndEnumExtents(&self, handle: u64) -> HRESULT;
    unsafe fn GetCodeNotification(&self, flags: *mut u32) -> HRESULT;
    unsafe fn SetCodeNotification(&self, flags: u32) -> HRESULT;
    unsafe fn Request(
        &self,
        request_code: u32,
        input_size: u32,
        input: *mut u8,
        output_size: u32,
        output: *mut u8,
    ) -> HRESULT;
    unsafe fn GetRepresentativeEntryAddress(&self, address: *mut u64) -> HRESULT;
}

#[windows::core::interface("ECD73800-22CA-4B0D-AB55-E9BA7E6318A5")]
unsafe trait IXCLRDataMethodInstance: IUnknown {
    unsafe fn GetTypeInstance(&self, type_instance: *mut *mut c_void) -> HRESULT;
    unsafe fn GetDefinition(&self, method: *mut *mut c_void) -> HRESULT;
    unsafe fn GetTokenAndScope(&self, token: *mut u32, module: *mut *mut c_void) -> HRESULT;
    unsafe fn GetName(
        &self,
        flags: u32,
        buffer_length: u32,
        name_length: *mut u32,
        name: *mut u16,
    ) -> HRESULT;
    unsafe fn GetFlags(&self, flags: *mut u32) -> HRESULT;
    unsafe fn IsSameObject(&self, method: *mut c_void) -> HRESULT;
    unsafe fn GetEnCVersion(&self, version: *mut u32) -> HRESULT;
    unsafe fn GetNumTypeArguments(&self, count: *mut u32) -> HRESULT;
    unsafe fn GetTypeArgumentByIndex(&self, index: u32, type_instance: *mut *mut c_void)
        -> HRESULT;
    unsafe fn GetILOffsetsByAddress(
        &self,
        address: u64,
        offset_count: u32,
        offsets_needed: *mut u32,
        offsets: *mut u32,
    ) -> HRESULT;
    unsafe fn GetAddressRangesByILOffset(
        &self,
        offset: u32,
        range_count: u32,
        ranges_needed: *mut u32,
        ranges: *mut c_void,
    ) -> HRESULT;
    unsafe fn GetILAddressMap(
        &self,
        map_count: u32,
        maps_needed: *mut u32,
        maps: *mut c_void,
    ) -> HRESULT;
    unsafe fn StartEnumExtents(&self, handle: *mut u64) -> HRESULT;
    unsafe fn EnumExtent(&self, handle: *mut u64, extent: *mut c_void) -> HRESULT;
    unsafe fn EndEnumExtents(&self, handle: u64) -> HRESULT;
    unsafe fn Request(
        &self,
        request_code: u32,
        input_size: u32,
        input: *mut u8,
        output_size: u32,
        output: *mut u8,
    ) -> HRESULT;
    unsafe fn GetRepresentativeEntryAddress(&self, address: *mut u64) -> HRESULT;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedRuntimeInfo {
    pub coreclr_path: PathBuf,
    pub dac_path: PathBuf,
    pub coreclr_file_version: (u32, u32),
    pub dac_file_version: (u32, u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedMethodCandidate {
    pub token: u32,
    pub signature_hex: String,
    pub signature_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedMethodInfo {
    pub token: u32,
    pub matching_method_count: u32,
    pub matching_method_candidates: Vec<ManagedMethodCandidate>,
    pub matching_method_candidates_truncated: bool,
    pub resolved_method: String,
    pub signature_hex: String,
    pub code_notification_flags: u32,
    pub representative_entry_address: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedCodeAvailability {
    Available,
    PendingJit,
}

#[windows::core::implement(ICLRDataTarget, ICLRDataTarget2)]
struct DbgEngDataTarget {
    data_spaces: IDebugDataSpaces4,
    symbols: IDebugSymbols5,
    system_objects: IDebugSystemObjects,
    advanced: IDebugAdvanced3,
    allow_target_writes: bool,
}

impl ICLRDataTarget_Impl for DbgEngDataTarget_Impl {
    unsafe fn GetMachineType(&self, machine_type: *mut u32) -> HRESULT {
        if machine_type.is_null() {
            return E_POINTER;
        }
        unsafe { *machine_type = IMAGE_FILE_MACHINE_AMD64.0 as u32 };
        HRESULT(0)
    }

    unsafe fn GetPointerSize(&self, pointer_size: *mut u32) -> HRESULT {
        if pointer_size.is_null() {
            return E_POINTER;
        }
        unsafe { *pointer_size = size_of::<u64>() as u32 };
        HRESULT(0)
    }

    unsafe fn GetImageBase(&self, image_path: PCWSTR, base_address: *mut u64) -> HRESULT {
        if image_path.is_null() || base_address.is_null() {
            return E_INVALIDARG;
        }
        let mut index = 0;
        let mut base = 0;
        match unsafe {
            self.symbols
                .GetModuleByModuleNameWide(image_path, 0, Some(&mut index), Some(&mut base))
        } {
            Ok(()) => {
                unsafe { *base_address = base };
                HRESULT(0)
            }
            Err(error) => error.code(),
        }
    }

    unsafe fn ReadVirtual(
        &self,
        address: u64,
        buffer: *mut u8,
        bytes_requested: u32,
        bytes_read: *mut u32,
    ) -> HRESULT {
        if buffer.is_null() || bytes_read.is_null() {
            return E_POINTER;
        }
        match unsafe {
            self.data_spaces
                .ReadVirtual(address, buffer.cast(), bytes_requested, Some(bytes_read))
        } {
            Ok(()) => HRESULT(0),
            Err(_) if unsafe { *bytes_read } != 0 => HRESULT(0),
            Err(error) => error.code(),
        }
    }

    unsafe fn WriteVirtual(
        &self,
        address: u64,
        buffer: *mut u8,
        bytes_requested: u32,
        bytes_written: *mut u32,
    ) -> HRESULT {
        if buffer.is_null() || bytes_written.is_null() {
            return E_POINTER;
        }
        if !self.allow_target_writes {
            return E_ACCESSDENIED;
        }
        match unsafe {
            self.data_spaces.WriteVirtual(
                address,
                buffer.cast(),
                bytes_requested,
                Some(bytes_written),
            )
        } {
            Ok(()) => HRESULT(0),
            Err(_) if unsafe { *bytes_written } != 0 => HRESULT(0),
            Err(error) => error.code(),
        }
    }

    unsafe fn GetTLSValue(&self, _: u32, _: u32, _: *mut u64) -> HRESULT {
        E_NOTIMPL
    }

    unsafe fn SetTLSValue(&self, _: u32, _: u32, _: u64) -> HRESULT {
        E_ACCESSDENIED
    }

    unsafe fn GetCurrentThreadID(&self, thread_id: *mut u32) -> HRESULT {
        if thread_id.is_null() {
            return E_POINTER;
        }
        match unsafe { self.system_objects.GetCurrentThreadSystemId() } {
            Ok(id) => {
                unsafe { *thread_id = id };
                HRESULT(0)
            }
            Err(error) => error.code(),
        }
    }

    unsafe fn GetThreadContext(
        &self,
        thread_id: u32,
        context_flags: u32,
        context_size: u32,
        context: *mut u8,
    ) -> HRESULT {
        if context.is_null() {
            return E_POINTER;
        }
        let mut current_thread = 0;
        let thread_result = unsafe { self.GetCurrentThreadID(&mut current_thread) };
        if thread_result.is_err() {
            return thread_result;
        }
        if thread_id != current_thread || context_size < size_of::<CONTEXT>() as u32 {
            return E_INVALIDARG;
        }
        let native_context = unsafe { &mut *context.cast::<CONTEXT>() };
        native_context.ContextFlags =
            windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(context_flags);
        match unsafe {
            self.advanced
                .GetThreadContext(native_context as *mut CONTEXT as *mut c_void, context_size)
        } {
            Ok(()) => HRESULT(0),
            Err(error) => error.code(),
        }
    }

    unsafe fn SetThreadContext(&self, _: u32, _: u32, _: *mut u8) -> HRESULT {
        E_ACCESSDENIED
    }

    unsafe fn Request(&self, _: u32, _: u32, _: *mut u8, _: u32, _: *mut u8) -> HRESULT {
        E_NOTIMPL
    }
}

impl ICLRDataTarget2_Impl for DbgEngDataTarget_Impl {
    unsafe fn AllocVirtual(
        &self,
        address: u64,
        size: u32,
        type_flags: u32,
        protect_flags: u32,
        allocation: *mut u64,
    ) -> HRESULT {
        if allocation.is_null() {
            return E_POINTER;
        }
        if !self.allow_target_writes {
            return E_ACCESSDENIED;
        }
        let handle = match unsafe { self.system_objects.GetCurrentProcessHandle() } {
            Ok(handle) => handle,
            Err(error) => return error.code(),
        };
        let allocation_result = unsafe {
            VirtualAllocEx(
                windows::Win32::Foundation::HANDLE(handle as *mut c_void),
                Some(address as *const c_void),
                size as usize,
                windows::Win32::System::Memory::VIRTUAL_ALLOCATION_TYPE(type_flags),
                windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(protect_flags),
            )
        };
        if allocation_result.is_null() {
            return windows::core::Error::from_win32().code();
        }
        unsafe { *allocation = allocation_result as u64 };
        HRESULT(0)
    }

    unsafe fn FreeVirtual(&self, address: u64, size: u32, type_flags: u32) -> HRESULT {
        if !self.allow_target_writes {
            return E_ACCESSDENIED;
        }
        let handle = match unsafe { self.system_objects.GetCurrentProcessHandle() } {
            Ok(handle) => handle,
            Err(error) => return error.code(),
        };
        match unsafe {
            VirtualFreeEx(
                windows::Win32::Foundation::HANDLE(handle as *mut c_void),
                address as *mut c_void,
                size as usize,
                windows::Win32::System::Memory::VIRTUAL_FREE_TYPE(type_flags),
            )
        } {
            Ok(()) => HRESULT(0),
            Err(error) => error.code(),
        }
    }
}

pub struct CoreClrDacBridge {
    process: IXCLRDataProcess,
    method: Option<IXCLRDataMethodDefinition>,
    method_instance: Option<IXCLRDataMethodInstance>,
    managed_module_path: Option<PathBuf>,
    method_token: u32,
    method_signature: Vec<u8>,
    matching_method_count: u32,
    matching_method_candidates: Vec<ManagedMethodCandidate>,
    matching_method_candidates_truncated: bool,
    runtime_info: ManagedRuntimeInfo,
    // COM interfaces must release before the callback object and its DAC module unload.
    _target: ICLRDataTarget2,
    _dac_module: LoadedModule,
}

impl CoreClrDacBridge {
    pub fn open(
        session: &DebuggerSession,
        coreclr_path: &Path,
        allow_target_writes: bool,
    ) -> anyhow::Result<Self> {
        ensure!(
            size_of::<usize>() == size_of::<u64>(),
            "the CoreCLR DAC bridge supports only x64 debugger hosts"
        );
        ensure!(
            coreclr_path.is_file(),
            "the selected CoreCLR module path does not exist: {}",
            coreclr_path.display()
        );
        let dac_path = coreclr_path
            .parent()
            .map(|parent| parent.join("mscordaccore.dll"))
            .context("the CoreCLR module path has no parent directory")?;
        ensure!(
            dac_path.is_file(),
            "an exact CoreCLR sibling mscordaccore.dll was not found"
        );

        let coreclr_version = file_version(coreclr_path)?;
        let dac_version = file_version(&dac_path)?;
        ensure!(
            coreclr_version == dac_version,
            "CoreCLR and mscordaccore.dll file versions do not match exactly"
        );

        let target: ICLRDataTarget2 = DbgEngDataTarget {
            data_spaces: session.data_spaces.clone(),
            symbols: session.symbols.clone(),
            system_objects: session.system_objects.clone(),
            advanced: session.client.cast().context("querying IDebugAdvanced3")?,
            allow_target_writes,
        }
        .into();
        let dac_module = LoadedModule::load(&dac_path, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR)?;
        let create_instance: ClrDataCreateInstance = unsafe {
            let procedure =
                GetProcAddress(dac_module.0, windows::core::s!("CLRDataCreateInstance"))
                    .context("the matching DAC does not export CLRDataCreateInstance")?;
            std::mem::transmute(procedure)
        };
        let mut raw_process = std::ptr::null_mut();
        unsafe { create_instance(&IXCLRDataProcess::IID, target.as_raw(), &mut raw_process).ok() }
            .context("CLRDataCreateInstance failed")?;
        let process = ensure_interface::<IXCLRDataProcess>(
            raw_process,
            "CLRDataCreateInstance reported success without returning IXCLRDataProcess",
        )?;

        Ok(Self {
            process,
            method: None,
            method_instance: None,
            managed_module_path: None,
            method_token: 0,
            method_signature: Vec::new(),
            matching_method_count: 0,
            matching_method_candidates: Vec::new(),
            matching_method_candidates_truncated: false,
            runtime_info: ManagedRuntimeInfo {
                coreclr_path: coreclr_path.to_path_buf(),
                dac_path,
                coreclr_file_version: coreclr_version,
                dac_file_version: dac_version,
            },
            _target: target,
            _dac_module: dac_module,
        })
    }

    pub fn runtime_info(&self) -> &ManagedRuntimeInfo {
        &self.runtime_info
    }

    pub fn enable_module_load_notifications(&self) -> anyhow::Result<()> {
        unsafe {
            self.process
                .SetOtherNotificationFlags(CLRDATA_NOTIFY_ON_MODULE_LOAD)
                .ok()
        }
        .context("requesting CLR managed-module load notifications")
    }

    pub fn disable_module_load_notifications(&self) -> anyhow::Result<()> {
        unsafe { self.process.SetOtherNotificationFlags(0).ok() }
            .context("disabling CLR managed-module load notifications")
    }

    pub fn is_module_loaded(&self, managed_module_path: &Path) -> anyhow::Result<bool> {
        Ok(self.find_module_by_path(managed_module_path)?.is_some())
    }

    pub fn resolve_and_notify(
        &mut self,
        managed_module_path: &Path,
        fully_qualified_method: &str,
        signature_blob: Option<&[u8]>,
    ) -> anyhow::Result<(ManagedMethodInfo, ManagedCodeAvailability)> {
        self.resolve_method(
            managed_module_path,
            fully_qualified_method,
            signature_blob,
            true,
        )
    }

    pub fn resolve_read_only(
        &mut self,
        managed_module_path: &Path,
        fully_qualified_method: &str,
        signature_blob: Option<&[u8]>,
    ) -> anyhow::Result<(ManagedMethodInfo, ManagedCodeAvailability)> {
        self.resolve_method(
            managed_module_path,
            fully_qualified_method,
            signature_blob,
            false,
        )
    }

    pub fn refresh_method_code(&mut self) -> anyhow::Result<ManagedMethodInfo> {
        let module_path = self
            .managed_module_path
            .as_deref()
            .context("no managed method has been resolved for this bridge")?;
        let module = self
            .find_module_by_path(module_path)?
            .context("the resolved managed module is no longer available through the DAC")?;
        let method = unsafe {
            let mut raw = std::ptr::null_mut();
            module
                .GetMethodDefinitionByToken(self.method_token, &mut raw)
                .ok()?;
            ensure_interface::<IXCLRDataMethodDefinition>(
                raw,
                "the DAC returned no method definition for the resolved token",
            )
        }
        .context("reopening the managed method definition after CLR code generation")?;
        self.method = Some(method);
        self.method_instance = None;
        let mut info = self.populate_method_info()?;
        info.matching_method_count = self.matching_method_count;
        info.matching_method_candidates = self.matching_method_candidates.clone();
        info.matching_method_candidates_truncated = self.matching_method_candidates_truncated;
        info.signature_hex = signature_hex(&self.method_signature).0;
        if info.representative_entry_address.is_none() {
            bail!("the managed method does not have a representative native entry address yet");
        }
        Ok(info)
    }

    fn resolve_method(
        &mut self,
        managed_module_path: &Path,
        fully_qualified_method: &str,
        signature_blob: Option<&[u8]>,
        request_code_notification: bool,
    ) -> anyhow::Result<(ManagedMethodInfo, ManagedCodeAvailability)> {
        if let Some(signature) = signature_blob {
            ensure!(
                !signature.is_empty(),
                "the CoreCLR DAC bridge signature selector must not be empty"
            );
        }
        let module = self
            .find_module_by_path(managed_module_path)?
            .context("the DbgEng-selected managed module is not present in the matching DAC module enumeration")?;
        let metadata = MetadataImport::open(managed_module_path)?;
        let method_name = wide(fully_qualified_method)?;
        let mut enumeration = 0;
        unsafe {
            module
                .StartEnumMethodDefinitionsByName(PCWSTR(method_name.as_ptr()), 0, &mut enumeration)
                .ok()
        }
        .context("starting managed method definition enumeration")?;

        let result = (|| -> anyhow::Result<_> {
            let mut candidates = Vec::new();
            let mut candidates_truncated = false;
            let mut selected = None;
            let mut matching_count = 0;
            loop {
                let mut raw = std::ptr::null_mut();
                let status =
                    unsafe { module.EnumMethodDefinitionByName(&mut enumeration, &mut raw) };
                if status == S_FALSE {
                    break;
                }
                status
                    .ok()
                    .context("enumerating managed method definitions")?;
                let method = ensure_interface::<IXCLRDataMethodDefinition>(
                    raw,
                    "the DAC returned a null managed method definition",
                )?;
                let mut token = 0;
                unsafe {
                    method
                        .GetTokenAndScope(&mut token, std::ptr::null_mut())
                        .ok()
                }
                .context("obtaining a managed method definition token")?;
                ensure!(token != 0, "the DAC returned a zero managed method token");
                let signature = metadata.method_signature(token)?;
                if candidates.len() < MAX_METHOD_CANDIDATES {
                    let (signature_hex, signature_truncated) = signature_hex(&signature);
                    candidates.push(ManagedMethodCandidate {
                        token,
                        signature_hex,
                        signature_truncated,
                    });
                } else {
                    candidates_truncated = true;
                }
                let matches = match signature_blob {
                    Some(expected) => expected == signature.as_slice(),
                    None => true,
                };
                if matches {
                    matching_count += 1;
                    if matching_count == 1 {
                        selected = Some((method, token, signature));
                    }
                }
            }
            Ok((candidates, candidates_truncated, matching_count, selected))
        })();
        unsafe { module.EndEnumMethodDefinitionsByName(enumeration).ok() }
            .context("ending managed method definition enumeration")?;
        let (candidates, candidates_truncated, matching_count, selected) = result?;
        ensure!(
            matching_count != 0,
            "the requested managed method was not found in the selected module"
        );
        if signature_blob.is_none() && matching_count != 1 {
            bail!(
                "the requested managed method is ambiguous. Supply --signature with the exact ECMA-335 MethodDef signature bytes"
            );
        }
        if signature_blob.is_some() && matching_count != 1 {
            bail!("more than one managed method definition matched the supplied exact metadata signature");
        }
        let (method, token, signature) =
            selected.context("no managed method matched the supplied signature")?;
        self.method = Some(method);
        self.method_instance = None;
        let mut info = self.populate_method_info()?;
        info.matching_method_count = matching_count;
        info.matching_method_candidates = candidates.clone();
        info.matching_method_candidates_truncated = candidates_truncated;
        info.signature_hex = signature_hex(&signature).0;
        self.managed_module_path = Some(managed_module_path.to_path_buf());
        self.method_token = token;
        self.method_signature = signature;
        self.matching_method_count = matching_count;
        self.matching_method_candidates = candidates;
        self.matching_method_candidates_truncated = candidates_truncated;
        if request_code_notification {
            unsafe {
                self.method
                    .as_ref()
                    .expect("method was assigned")
                    .SetCodeNotification(info.code_notification_flags)
                    .ok()
            }
            .context("requesting CLR code-generation notification")?;
        }
        let availability = if info.representative_entry_address.is_some() {
            ManagedCodeAvailability::Available
        } else {
            ManagedCodeAvailability::PendingJit
        };
        Ok((info, availability))
    }

    fn find_module_by_path(&self, expected_path: &Path) -> anyhow::Result<Option<IXCLRDataModule>> {
        unsafe { self.process.Flush().ok() }.context("refreshing the DAC process state")?;
        let mut enumeration = 0;
        let start_status = unsafe { self.process.StartEnumModules(&mut enumeration) };
        if start_status == S_FALSE {
            return Ok(None);
        }
        start_status
            .ok()
            .context("starting managed module enumeration")?;
        let result = (|| -> anyhow::Result<_> {
            loop {
                let mut raw = std::ptr::null_mut();
                let status = unsafe { self.process.EnumModule(&mut enumeration, &mut raw) };
                if status == S_FALSE {
                    return Ok(None);
                }
                status.ok().context("enumerating managed modules")?;
                let module = ensure_interface::<IXCLRDataModule>(
                    raw,
                    "the DAC returned a null managed module",
                )?;
                let mut path = vec![0u16; 32 * 1024];
                let mut path_length = 0;
                unsafe {
                    module
                        .GetFileName(path.len() as u32, &mut path_length, path.as_mut_ptr())
                        .ok()
                }
                .context("getting a managed module file name")?;
                let actual_path = utf16_path(&path)?;
                if module_paths_match(expected_path, &actual_path) {
                    return Ok(Some(module));
                }
            }
        })();
        unsafe { self.process.EndEnumModules(enumeration).ok() }
            .context("ending managed module enumeration")?;
        result
    }

    fn populate_method_info(&mut self) -> anyhow::Result<ManagedMethodInfo> {
        let method = self
            .method
            .as_ref()
            .context("no managed method is selected")?;
        let mut name = vec![0u16; MAX_WIDE_CHARS];
        let mut name_length = 0;
        unsafe {
            method
                .GetName(0, name.len() as u32, &mut name_length, name.as_mut_ptr())
                .ok()
        }
        .context("reading the managed method name")?;
        let mut token = 0;
        unsafe {
            method
                .GetTokenAndScope(&mut token, std::ptr::null_mut())
                .ok()
        }
        .context("reading the managed method token")?;
        let method_instance = find_method_instance(method)?;
        let representative_entry_address = if let Some(instance) = method_instance.as_ref() {
            let mut address = 0;
            match unsafe { instance.GetRepresentativeEntryAddress(&mut address) } {
                status if status == E_UNEXPECTED => None,
                status => {
                    status
                        .ok()
                        .context("reading a managed method native entry address")?;
                    (address != 0).then_some(address)
                }
            }
        } else {
            None
        };
        self.method_instance = method_instance;
        Ok(ManagedMethodInfo {
            token,
            matching_method_count: 0,
            matching_method_candidates: Vec::new(),
            matching_method_candidates_truncated: false,
            resolved_method: utf16_string(&name, "managed method name")?,
            signature_hex: String::new(),
            code_notification_flags: CLRDATA_METHNOTIFY_GENERATED | CLRDATA_METHNOTIFY_DISCARDED,
            representative_entry_address,
        })
    }
}

struct LoadedModule(HMODULE);

impl LoadedModule {
    fn load(
        path: &Path,
        flags: windows::Win32::System::LibraryLoader::LOAD_LIBRARY_FLAGS,
    ) -> anyhow::Result<Self> {
        let path = wide_path(path)?;
        let module = unsafe { LoadLibraryExW(PCWSTR(path.as_ptr()), None, flags) }
            .context("loading the requested module")?;
        Ok(Self(module))
    }

    fn load_system(name: &str) -> anyhow::Result<Self> {
        let name = wide(name)?;
        let module =
            unsafe { LoadLibraryExW(PCWSTR(name.as_ptr()), None, LOAD_LIBRARY_SEARCH_SYSTEM32) }
                .context("loading the requested system module")?;
        Ok(Self(module))
    }
}

impl Drop for LoadedModule {
    fn drop(&mut self) {
        unsafe {
            let _ = FreeLibrary(self.0);
        }
    }
}

type ClrDataCreateInstance =
    unsafe extern "system" fn(*const GUID, *mut c_void, *mut *mut c_void) -> HRESULT;
type MetaDataGetDispenser =
    unsafe extern "system" fn(*const GUID, *const GUID, *mut *mut c_void) -> HRESULT;

struct MetadataImport {
    importer: windows::Win32::System::WinRT::Metadata::IMetaDataImport,
    _mscoree: LoadedModule,
}

impl MetadataImport {
    fn open(module_path: &Path) -> anyhow::Result<Self> {
        use windows::Win32::System::WinRT::Metadata::{
            CLSID_CorMetaDataDispenser, IMetaDataDispenser, IMetaDataImport,
        };

        let mscoree = LoadedModule::load_system("mscoree.dll").context("loading mscoree.dll")?;
        let get_dispenser: MetaDataGetDispenser = unsafe {
            let procedure = GetProcAddress(mscoree.0, windows::core::s!("MetaDataGetDispenser"))
                .context("mscoree.dll does not export MetaDataGetDispenser")?;
            std::mem::transmute(procedure)
        };
        let mut raw_dispenser = std::ptr::null_mut();
        unsafe {
            get_dispenser(
                &CLSID_CorMetaDataDispenser,
                &IMetaDataDispenser::IID,
                &mut raw_dispenser,
            )
            .ok()
        }
        .context("creating the metadata dispenser")?;
        let dispenser = ensure_interface::<IMetaDataDispenser>(
            raw_dispenser,
            "MetaDataGetDispenser returned a null metadata dispenser",
        )?;
        let path = wide_path(module_path)?;
        let importer = unsafe {
            dispenser
                .OpenScope(PCWSTR(path.as_ptr()), 0, &IMetaDataImport::IID)
                .and_then(|unknown| unknown.cast())
        }
        .context("opening the selected managed module metadata")?;
        Ok(Self {
            importer,
            _mscoree: mscoree,
        })
    }

    fn method_signature(&self, method: u32) -> anyhow::Result<Vec<u8>> {
        let mut signature = std::ptr::null_mut();
        let mut signature_size = 0;
        unsafe {
            self.importer.GetMethodProps(
                method,
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut signature,
                &mut signature_size,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }
        .context("reading a managed MethodDef signature")?;
        ensure!(
            !signature.is_null() && signature_size != 0,
            "the managed MethodDef had no metadata signature"
        );
        Ok(unsafe { std::slice::from_raw_parts(signature, signature_size as usize).to_vec() })
    }
}

fn find_method_instance(
    method: &IXCLRDataMethodDefinition,
) -> anyhow::Result<Option<IXCLRDataMethodInstance>> {
    let mut enumeration = 0;
    let start_status = unsafe { method.StartEnumInstances(std::ptr::null_mut(), &mut enumeration) };
    if start_status == S_FALSE {
        return Ok(None);
    }
    start_status
        .ok()
        .context("starting managed method instance enumeration")?;
    let result = (|| -> anyhow::Result<_> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe { method.EnumInstance(&mut enumeration, &mut raw) };
        if status == S_FALSE {
            return Ok(None);
        }
        status
            .ok()
            .context("enumerating managed method instances")?;
        Ok(Some(ensure_interface::<IXCLRDataMethodInstance>(
            raw,
            "the DAC returned a null managed method instance",
        )?))
    })();
    unsafe { method.EndEnumInstances(enumeration).ok() }
        .context("ending managed method instance enumeration")?;
    result
}

fn ensure_interface<T: Interface>(raw: *mut c_void, message: &str) -> anyhow::Result<T> {
    ensure!(!raw.is_null(), "{message}");
    Ok(unsafe { T::from_raw(raw) })
}

fn file_version(path: &Path) -> anyhow::Result<(u32, u32)> {
    let path = wide_path(path)?;
    let mut ignored = 0;
    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(path.as_ptr()), Some(&mut ignored)) };
    ensure!(size != 0, "reading the file-version resource size failed");
    let mut buffer = vec![0u8; size as usize];
    unsafe { GetFileVersionInfoW(PCWSTR(path.as_ptr()), 0, size, buffer.as_mut_ptr().cast()) }
        .context("reading the file-version resource")?;
    let root = [b'\\' as u16, 0];
    let mut value = std::ptr::null_mut();
    let mut value_size = 0;
    ensure!(
        unsafe {
            VerQueryValueW(
                buffer.as_ptr().cast(),
                PCWSTR(root.as_ptr()),
                &mut value,
                &mut value_size,
            )
            .as_bool()
        },
        "reading the fixed file-version resource failed"
    );
    ensure!(
        !value.is_null() && value_size as usize >= size_of::<VS_FIXEDFILEINFO>(),
        "the fixed file-version resource was missing or truncated"
    );
    let version = unsafe { &*value.cast::<VS_FIXEDFILEINFO>() };
    ensure!(
        version.dwSignature == VS_FFI_SIGNATURE as u32,
        "the fixed file-version resource had an invalid signature"
    );
    Ok((version.dwFileVersionMS, version.dwFileVersionLS))
}

fn wide(value: &str) -> anyhow::Result<Vec<u16>> {
    ensure!(
        !value.encode_utf16().any(|character| character == 0),
        "CoreCLR DAC input must not contain an embedded NUL"
    );
    Ok(value.encode_utf16().chain(std::iter::once(0)).collect())
}

fn wide_path(path: &Path) -> anyhow::Result<Vec<u16>> {
    let mut value = path.as_os_str().encode_wide().collect::<Vec<_>>();
    ensure!(
        !value.contains(&0),
        "CoreCLR DAC paths must not contain an embedded NUL"
    );
    value.push(0);
    Ok(value)
}

fn utf16_string(value: &[u16], name: &str) -> anyhow::Result<String> {
    let length = value
        .iter()
        .position(|character| *character == 0)
        .with_context(|| format!("{name} was not NUL terminated"))?;
    String::from_utf16(&value[..length]).with_context(|| format!("{name} was invalid UTF-16"))
}

fn utf16_path(value: &[u16]) -> anyhow::Result<PathBuf> {
    Ok(PathBuf::from(utf16_string(value, "managed module path")?))
}

fn module_paths_match(expected: &Path, actual: &Path) -> bool {
    let expected = expected.to_string_lossy();
    let actual = actual.to_string_lossy();
    expected.eq_ignore_ascii_case(&actual)
        || expected
            .rsplit(['\\', '/'])
            .next()
            .zip(actual.rsplit(['\\', '/']).next())
            .is_some_and(|(expected, actual)| expected.eq_ignore_ascii_case(actual))
}

fn signature_hex(signature: &[u8]) -> (String, bool) {
    let maximum_bytes = (MAX_SIGNATURE_HEX_CHARS - 1) / 2;
    let copied = signature.len().min(maximum_bytes);
    (
        signature[..copied]
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect(),
        copied != signature.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_nul_terminated_utf16() {
        assert_eq!(
            utf16_string(&['t' as u16, 'e' as u16, 's' as u16, 't' as u16, 0], "test").unwrap(),
            "test"
        );
    }

    #[test]
    fn rejects_unterminated_utf16() {
        assert!(utf16_string(&[1u16; 4], "test").is_err());
    }

    #[test]
    fn truncates_signature_hex_at_abi_limit() {
        let (hex, truncated) = signature_hex(&vec![0xAB; MAX_SIGNATURE_HEX_CHARS]);
        assert_eq!(hex.len(), MAX_SIGNATURE_HEX_CHARS - 2);
        assert!(truncated);
    }

    #[test]
    fn coreclr_interface_iids_match_the_pinned_idl() {
        assert_eq!(
            IXCLRDataProcess::IID,
            GUID::from_u128(0x5c552ab6_fc09_4cb3_8e36_22fa03c798b7)
        );
        assert_eq!(
            IXCLRDataModule::IID,
            GUID::from_u128(0x88e32849_0a0a_4cb0_9022_7cd2e9e139e2)
        );
        assert_eq!(
            IXCLRDataMethodDefinition::IID,
            GUID::from_u128(0xaaf60008_fb2c_420b_8fb1_42d244a54a97)
        );
        assert_eq!(
            IXCLRDataMethodInstance::IID,
            GUID::from_u128(0xecd73800_22ca_4b0d_ab55_e9ba7e6318a5)
        );
    }
}
