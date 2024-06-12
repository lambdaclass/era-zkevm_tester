use std::str::FromStr;

use zk_evm::ethereum_types::U256;
use zk_evm::tracing::*;
use zk_evm::zkevm_opcode_defs::{FatPointer, Opcode, UMAOpcode};
use zk_evm::{
    reference_impls::memory::SimpleMemory,
    vm_state::*,
    zkevm_opcode_defs::decoding::{AllowedPcOrImm, EncodingModeProduction, VmEncodingMode},
};
use zkevm_assembly::Assembly;

use crate::runners::compiler_tests::{get_tracing_mode, VmTracingOptions};

use super::hashmap_based_memory::SimpleHashmapMemory;

#[derive(Debug)]
pub struct DummyVmTracer<const N: usize = 8, E: VmEncodingMode<N> = EncodingModeProduction> {
    _marker: std::marker::PhantomData<E>,
}

impl<const N: usize, E: VmEncodingMode<N>> DummyVmTracer<N, E> {
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

impl<const N: usize, E: VmEncodingMode<N>> Tracer<N, E> for DummyVmTracer<N, E> {
    const CALL_BEFORE_DECODING: bool = true;
    const CALL_AFTER_DECODING: bool = true;
    const CALL_BEFORE_EXECUTION: bool = true;
    const CALL_AFTER_EXECUTION: bool = true;

    type SupportedMemory = SimpleMemory;

    fn before_decoding(
        &mut self,
        state: VmLocalStateData<'_, N, E>,
        _memory: &Self::SupportedMemory,
    ) {
        if get_tracing_mode() != VmTracingOptions::ManualVerbose {
            return;
        }
        dbg!(state);
    }
    fn after_decoding(
        &mut self,
        _state: VmLocalStateData<'_, N, E>,
        data: AfterDecodingData<N, E>,
        _memory: &Self::SupportedMemory,
    ) {
        if get_tracing_mode() != VmTracingOptions::ManualVerbose {
            return;
        }
        dbg!(data);
    }
    fn before_execution(
        &mut self,
        _state: VmLocalStateData<'_, N, E>,
        data: BeforeExecutionData<N, E>,
        _memory: &Self::SupportedMemory,
    ) {
        if get_tracing_mode() != VmTracingOptions::ManualVerbose {
            return;
        }
        dbg!(data);
    }
    fn after_execution(
        &mut self,
        _state: VmLocalStateData<'_, N, E>,
        data: AfterExecutionData<N, E>,
        _memory: &Self::SupportedMemory,
    ) {
        if get_tracing_mode() != VmTracingOptions::ManualVerbose {
            return;
        }
        dbg!(data);
    }
}

use crate::Address;

#[derive(Debug)]
pub struct DebugTracerWithAssembly<
    const N: usize = 8,
    E: VmEncodingMode<N> = EncodingModeProduction,
> {
    pub current_code_address: Address,
    pub code_address_to_assembly: std::collections::HashMap<Address, Assembly>,
    pub _marker: std::marker::PhantomData<E>,
}

impl<const N: usize, E: VmEncodingMode<N>> Tracer<N, E> for DebugTracerWithAssembly<N, E> {
    const CALL_BEFORE_DECODING: bool = true;
    const CALL_AFTER_DECODING: bool = true;
    const CALL_BEFORE_EXECUTION: bool = true;
    const CALL_AFTER_EXECUTION: bool = true;

    type SupportedMemory = SimpleHashmapMemory;

    fn before_decoding(
        &mut self,
        state: VmLocalStateData<'_, N, E>,
        _memory: &Self::SupportedMemory,
    ) {
        if get_tracing_mode() != VmTracingOptions::ManualVerbose {
            return;
        }
        println!("New cycle -------------------------");
        let pc = state.vm_local_state.callstack.get_current_stack().pc;
        if let Some(assembly) = self
            .code_address_to_assembly
            .get(&self.current_code_address)
        {
            if let Some(line) = assembly
                .pc_line_mapping
                .get(&(pc.as_u64() as usize))
                .copied()
            {
                let l = if line == 0 {
                    assembly.assembly_code.lines().next().unwrap()
                } else {
                    assembly.assembly_code.lines().skip(line).next().unwrap()
                };

                println!("Executing {}", l.trim());
                // if l.trim().contains("far_call") {
                //     println!("Breakpoint");
                // }
            }
        }
    }
    fn after_decoding(
        &mut self,
        _state: VmLocalStateData<'_, N, E>,
        _data: AfterDecodingData<N, E>,
        _memory: &Self::SupportedMemory,
    ) {
        if get_tracing_mode() != VmTracingOptions::ManualVerbose {
            return;
        }
    }
    fn before_execution(
        &mut self,
        state: VmLocalStateData<'_, N, E>,
        data: BeforeExecutionData<N, E>,
        memory: &Self::SupportedMemory,
    ) {
        // FIXME: this catches not only Evm contracts

        let opcode_variant = data.opcode.variant;
        let heap_page =
            heap_page_from_base(state.vm_local_state.callstack.current.base_memory_page).0;

        let src0_value = data.src0_value.value;

        let fat_ptr = FatPointer::from_u256(src0_value);

        let value = data.src1_value.value;

        const DEBUG_SLOT: u32 = 32 * 32;

        let debug_magic = U256::from_dec_str(
            "33509158800074003487174289148292687789659295220513886355337449724907776218753",
        )
        .unwrap();

        // Only `UMA` opcodes in the bootloader serve for vm hooks
        if !matches!(opcode_variant.opcode, Opcode::UMA(UMAOpcode::HeapWrite))
            || fat_ptr.offset != DEBUG_SLOT
            || value != debug_magic
        {
            // println!("I tried");
            return;
        }

        let how_to_print_value = memory.read_slot(heap_page, 32 + 1).value;
        let value_to_print = memory.read_slot(heap_page, 32 + 2).value;

        let print_as_hex_value =
            U256::from_str("0x00debdebdebdebdebdebdebdebdebdebdebdebdebdebdebdebdebdebdebdebde")
                .unwrap();
        let print_as_string_value =
            U256::from_str("0x00debdebdebdebdebdebdebdebdebdebdebdebdebdebdebdebdebdebdebdebdf")
                .unwrap();

        if how_to_print_value == print_as_hex_value {
            print!("PRINTED: ");
            println!("0x{:02x}", value_to_print);
        }

        if how_to_print_value == print_as_string_value {
            print!("PRINTED: ");
            let mut value = value_to_print.0;
            value.reverse();
            for limb in value {
                print!(
                    "{}",
                    String::from_utf8(limb.to_be_bytes().to_vec()).unwrap()
                );
            }
            println!("");
        }
    }
    fn after_execution(
        &mut self,
        state: VmLocalStateData<'_, N, E>,
        _data: AfterExecutionData<N, E>,
        _memory: &Self::SupportedMemory,
    ) {
        self.current_code_address = state
            .vm_local_state
            .callstack
            .get_current_stack()
            .code_address;
        if get_tracing_mode() != VmTracingOptions::ManualVerbose {
            return;
        }
        println!(
            "Registers: {:?}",
            state
                .vm_local_state
                .registers
                .iter()
                .map(|el| format!("0x{:064x}", el.value))
                .collect::<Vec<_>>()
        );
    }
}
