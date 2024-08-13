use std::str::FromStr;

use zk_evm::ethereum_types::U256;
use zk_evm::tracing::*;
use zk_evm::zkevm_opcode_defs::{FatPointer, Opcode, UMAOpcode};
use zk_evm::{
    vm_state::*,
    zkevm_opcode_defs::decoding::{EncodingModeProduction, VmEncodingMode},
};


use super::hashmap_based_memory::SimpleHashmapMemory;


#[derive(Debug)]
pub struct LambdaTracer<
    const N: usize = 8,
    E: VmEncodingMode<N> = EncodingModeProduction,
> {
    pub _marker: std::marker::PhantomData<E>,
}

impl<const N: usize, E: VmEncodingMode<N>> LambdaTracer<N, E> {
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

impl<const N: usize, E: VmEncodingMode<N>> Tracer<N, E> for LambdaTracer<N, E> {
    const CALL_BEFORE_DECODING: bool = true;
    const CALL_AFTER_DECODING: bool = true;
    const CALL_BEFORE_EXECUTION: bool = true;
    const CALL_AFTER_EXECUTION: bool = true;

    type SupportedMemory = SimpleHashmapMemory;

    fn before_decoding(
        &mut self,
        _state: VmLocalStateData<'_, N, E>,
        _memory: &Self::SupportedMemory,
    ) {
        
    }
    fn after_decoding(
        &mut self,
        _state: VmLocalStateData<'_, N, E>,
        _data: AfterDecodingData<N, E>,
        _memory: &Self::SupportedMemory,
    ) {
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
        _state: VmLocalStateData<'_, N, E>,
        _data: AfterExecutionData<N, E>,
        _memory: &Self::SupportedMemory,
    ) {
    }
}
